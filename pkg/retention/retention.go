package retention

import (
	"context"
	"fmt"

	glob "github.com/bmatcuk/doublestar/v4"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api/config"
	zcommon "zotregistry.dev/zot/pkg/common"
	zlog "zotregistry.dev/zot/pkg/log"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	"zotregistry.dev/zot/pkg/retention/types"
)

const (
	// reasons for gc.
	filteredByTagRules = "didn't meet any tag retention rule"
	filteredByTagNames = "didn't meet any tag 'patterns' rules"
	// reasons for retention.
	retainedStrFormat = "retained by %s policy"
)

type candidatesRules struct {
	candidates []*types.Candidate
	// tag retention rules
	rules []types.Rule
}

type policyManager struct {
	config   config.ImageRetention
	regex    *RegexMatcher
	log      zlog.Logger
	auditLog *zlog.Logger
}

func NewPolicyManager(config config.ImageRetention, log zlog.Logger, auditLog *zlog.Logger) policyManager {
	return policyManager{
		config:   config,
		regex:    NewRegexMatcher(),
		log:      log,
		auditLog: auditLog,
	}
}

func (p policyManager) HasDeleteUntagged(repo string) bool {
	if policy, err := p.getRepoPolicy(repo); err == nil {
		if policy.DeleteUntagged != nil {
			return *policy.DeleteUntagged
		}

		return true
	}

	// default
	return false
}

func (p policyManager) HasDeleteReferrer(repo string) bool {
	if policy, err := p.getRepoPolicy(repo); err == nil {
		return policy.DeleteReferrers
	}

	// default
	return false
}

func (p policyManager) HasTagRetention(repo string) bool {
	if policy, err := p.getRepoPolicy(repo); err == nil {
		return len(policy.KeepTags) > 0
	}

	// default
	return false
}

func (p policyManager) getRules(tagPolicy config.KeepTagsPolicy) []types.Rule {
	rules := make([]types.Rule, 0)

	if tagPolicy.MostRecentlyPulledCount != 0 {
		rules = append(rules, NewLatestPull(tagPolicy.MostRecentlyPulledCount))
	}

	if tagPolicy.MostRecentlyPushedCount != 0 {
		rules = append(rules, NewLatestPush(tagPolicy.MostRecentlyPushedCount))
	}

	if tagPolicy.PulledWithin != nil {
		rules = append(rules, NewDaysPull(*tagPolicy.PulledWithin))
	}

	if tagPolicy.PushedWithin != nil {
		rules = append(rules, NewDaysPush(*tagPolicy.PushedWithin))
	}

	return rules
}

func (p policyManager) GetRetainedTags(ctx context.Context, repoMeta mTypes.RepoMeta, index ispec.Index) []string {
	repo := repoMeta.Name

	matchedByName := make([]string, 0)

	candidates := GetCandidates(repoMeta)
	retainTags := make([]string, 0)

	// we need to make sure tags for which we can not find statistics in repoDB are not removed
	actualTags := getIndexTags(index)

	// find tags which are not in candidates list, if they are not in repoDB we want to keep them
	for _, tag := range actualTags {
		found := false

		for _, candidate := range candidates {
			if candidate.Tag == tag {
				found = true
			}
		}

		if !found {
			p.log.Info().Str("module", "retention").
				Bool("dry-run", p.config.DryRun).
				Str("repository", repo).
				Str("tag", tag).
				Str("decision", "keep").
				Str("reason", "tag statistics not found").Msg("will keep tag")

			retainTags = append(retainTags, tag)
		}
	}

	// group all tags by tag policy
	grouped := p.groupCandidatesByTagPolicy(repo, candidates)

	for _, candidates := range grouped {
		if zcommon.IsContextDone(ctx) {
			return nil
		}

		retainCandidates := candidates.candidates // copy
		// tag rules
		rules := candidates.rules

		for _, retainedByName := range retainCandidates {
			matchedByName = append(matchedByName, retainedByName.Tag)
		}

		rulesCandidates := make([]*types.Candidate, 0)

		// we retain candidates if any of the below rules are met (OR logic between rules)
		for _, rule := range rules {
			ruleCandidates := rule.Perform(retainCandidates)

			rulesCandidates = append(rulesCandidates, ruleCandidates...)
		}

		// if we applied any rule
		if len(rules) > 0 {
			retainCandidates = rulesCandidates
		} // else we retain just the one matching name rule

		for _, retainCandidate := range retainCandidates {
			// there may be duplicates
			if !zcommon.Contains(retainTags, retainCandidate.Tag) {
				// format reason log msg
				reason := fmt.Sprintf(retainedStrFormat, retainCandidate.RetainedBy)

				logAction(repo, "keep", reason, retainCandidate, p.config.DryRun, &p.log)

				retainTags = append(retainTags, retainCandidate.Tag)
			}
		}
	}

	// log tags which will be removed
	for _, candidateInfo := range candidates {
		if !zcommon.Contains(retainTags, candidateInfo.Tag) {
			var reason string
			if zcommon.Contains(matchedByName, candidateInfo.Tag) {
				reason = filteredByTagRules
			} else {
				reason = filteredByTagNames
			}

			logAction(repo, "delete", reason, candidateInfo, p.config.DryRun, &p.log)

			if p.auditLog != nil {
				logAction(repo, "delete", reason, candidateInfo, p.config.DryRun, p.auditLog)
			}
		}
	}

	return retainTags
}

func (p policyManager) getRepoPolicy(repo string) (config.RetentionPolicy, error) {
	for _, policy := range p.config.Policies {
		for _, pattern := range policy.Repositories {
			matched, err := glob.Match(pattern, repo)
			if err == nil && matched {
				return policy, nil
			}
		}
	}

	return config.RetentionPolicy{}, zerr.ErrRetentionPolicyNotFound
}

func (p policyManager) getTagPolicy(tag string, tagPolicies []config.KeepTagsPolicy,
) (config.KeepTagsPolicy, int, error) {
	for idx, tagPolicy := range tagPolicies {
		if p.regex.MatchesListOfRegex(tag, tagPolicy.Patterns) {
			return tagPolicy, idx, nil
		}
	}

	return config.KeepTagsPolicy{}, -1, zerr.ErrRetentionPolicyNotFound
}

// groups candidates by tag policies, tags which don't match any policy are automatically excluded from this map.
func (p policyManager) groupCandidatesByTagPolicy(repo string, candidates []*types.Candidate,
) map[int]candidatesRules {
	candidatesByTagPolicy := make(map[int]candidatesRules)

	// no need to check for error, at this point we have both repo policy for this repo and non nil tags policy
	repoPolicy, _ := p.getRepoPolicy(repo)

	for _, candidateInfo := range candidates {
		tagPolicy, tagPolicyID, err := p.getTagPolicy(candidateInfo.Tag, repoPolicy.KeepTags)
		if err != nil {
			// no tag policy found for the current candidate, skip it (will be gc'ed)
			continue
		}

		candidateInfo.RetainedBy = "patterns"

		if _, ok := candidatesByTagPolicy[tagPolicyID]; !ok {
			candidatesRules := candidatesRules{candidates: []*types.Candidate{candidateInfo}}
			candidatesRules.rules = p.getRules(tagPolicy)
			candidatesByTagPolicy[tagPolicyID] = candidatesRules
		} else {
			candidatesRules := candidatesByTagPolicy[tagPolicyID]
			candidatesRules.candidates = append(candidatesRules.candidates, candidateInfo)
			candidatesByTagPolicy[tagPolicyID] = candidatesRules
		}
	}

	return candidatesByTagPolicy
}

func logAction(repo, decision, reason string, candidate *types.Candidate, dryRun bool, log *zlog.Logger) {
	log.Info().Str("module", "retention").
		Bool("dry-run", dryRun).
		Str("repository", repo).
		Str("mediaType", candidate.MediaType).
		Str("digest", candidate.DigestStr).
		Str("tag", candidate.Tag).
		Str("lastPullTimestamp", candidate.PullTimestamp.String()).
		Str("pushTimestamp", candidate.PushTimestamp.String()).
		Str("decision", decision).
		Str("reason", reason).Msg("applied policy")
}

func getIndexTags(index ispec.Index) []string {
	tags := make([]string, 0)

	for _, desc := range index.Manifests {
		tag, ok := desc.Annotations[ispec.AnnotationRefName]
		if ok {
			tags = append(tags, tag)
		}
	}

	return tags
}
