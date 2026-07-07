package retention

import (
	"context"
	"fmt"
	"slices"
	"time"

	glob "github.com/bmatcuk/doublestar/v4"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/retention/types"
)

const (
	// reasons for gc.
	filteredByTagRules      = "didn't meet any tag retention rule"
	filteredByTagNames      = "didn't meet any tag 'patterns' rules"
	filteredByUntaggedRules = "didn't meet any untagged retention rule"
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

	// by default zot deletes untagged manifests if the config does not contain retention settings and gc is enabled
	return true
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

func (p policyManager) HasUntaggedRetention(repo string) bool {
	if policy, err := p.getRepoPolicy(repo); err == nil {
		return policy.KeepUntagged != nil && len(p.getUntaggedRules(*policy.KeepUntagged)) > 0
	}

	return false
}

func (p policyManager) getRules(tagPolicy config.KeepTagsPolicy) []types.Rule {
	return getRules(tagPolicy.MostRecentlyPulledCount, tagPolicy.MostRecentlyPushedCount,
		tagPolicy.PulledWithin, tagPolicy.PushedWithin)
}

func (p policyManager) getUntaggedRules(untaggedPolicy config.KeepUntaggedPolicy) []types.Rule {
	return getRules(untaggedPolicy.MostRecentlyPulledCount, untaggedPolicy.MostRecentlyPushedCount,
		untaggedPolicy.PulledWithin, untaggedPolicy.PushedWithin)
}

func getRules(mostRecentlyPulledCount, mostRecentlyPushedCount int,
	pulledWithin, pushedWithin *time.Duration,
) []types.Rule {
	rules := make([]types.Rule, 0)

	if mostRecentlyPulledCount != 0 {
		rules = append(rules, NewLatestPull(mostRecentlyPulledCount))
	}

	if mostRecentlyPushedCount != 0 {
		rules = append(rules, NewLatestPush(mostRecentlyPushedCount))
	}

	if pulledWithin != nil {
		rules = append(rules, NewDaysPull(*pulledWithin))
	}

	if pushedWithin != nil {
		rules = append(rules, NewDaysPush(*pushedWithin))
	}

	return rules
}

// GetRetainedTagsFromIndex uses only index information to match tags against patterns and determine
// a list of tags to be retained. This function is to be used only in case MetaDB information is not available,
// if the DB is not instantiated.
func (p policyManager) GetRetainedTagsFromIndex(ctx context.Context, repo string, index ispec.Index) []string {
	candidates := GetCandidatesFromIndex(index)
	retainTags := make([]string, 0)

	// group all tags by tag policy
	grouped := p.groupCandidatesByTagPolicy(repo, candidates)

	for _, candidates := range grouped {
		if zcommon.IsContextDone(ctx) {
			return nil
		}

		for _, retainCandidate := range candidates.candidates {
			// there may be duplicates
			if !slices.Contains(retainTags, retainCandidate.Tag) {
				reason := fmt.Sprintf(retainedStrFormat, retainCandidate.RetainedBy)

				logAction(repo, "keep", reason, retainCandidate, p.config.DryRun, &p.log)

				retainTags = append(retainTags, retainCandidate.Tag)
			}
		}
	}

	// log tags which will be removed
	for _, candidate := range candidates {
		if !slices.Contains(retainTags, candidate.Tag) {
			logAction(repo, "delete", filteredByTagNames, candidate, p.config.DryRun, &p.log)

			if p.auditLog != nil {
				logAction(repo, "delete", filteredByTagNames, candidate, p.config.DryRun, p.auditLog)
			}
		}
	}

	return retainTags
}

// GetRetainedTagsFromMetaDB uses MetaDB information to apply retention rules and obtain a list of tags to be retained.
func (p policyManager) GetRetainedTagsFromMetaDB(ctx context.Context, repoMeta mTypes.RepoMeta,
	index ispec.Index,
) []string {
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
			if !slices.Contains(retainTags, retainCandidate.Tag) {
				// format reason log msg
				reason := fmt.Sprintf(retainedStrFormat, retainCandidate.RetainedBy)

				logAction(repo, "keep", reason, retainCandidate, p.config.DryRun, &p.log)

				retainTags = append(retainTags, retainCandidate.Tag)
			}
		}
	}

	// log tags which will be removed
	for _, candidateInfo := range candidates {
		if !slices.Contains(retainTags, candidateInfo.Tag) {
			var reason string
			if slices.Contains(matchedByName, candidateInfo.Tag) {
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

func (p policyManager) GetRetainedUntaggedFromMetaDB(ctx context.Context, repoMeta mTypes.RepoMeta,
	index ispec.Index,
) []string {
	repo := repoMeta.Name
	policy, err := p.getRepoPolicy(repo)
	if err != nil || policy.KeepUntagged == nil {
		return nil
	}

	candidates := GetUntaggedCandidates(repoMeta, index)
	retainDigests := make([]string, 0)
	retainDigestsSet := make(map[string]struct{})
	candidateDigestsSet := make(map[string]struct{}, len(candidates))

	for _, candidate := range candidates {
		candidateDigestsSet[candidate.DigestStr] = struct{}{}
	}

	for _, digestStr := range getIndexUntaggedDigests(index) {
		if _, found := candidateDigestsSet[digestStr]; found {
			continue
		}

		if _, retained := retainDigestsSet[digestStr]; retained {
			continue
		}

		p.log.Info().Str("module", "retention").
			Bool("dry-run", p.config.DryRun).
			Str("repository", repo).
			Str("digest", digestStr).
			Str("reference", digestStr).
			Str("decision", "keep").
			Str("reason", "untagged manifest statistics not found").Msg("will keep untagged manifest")

		retainDigestsSet[digestStr] = struct{}{}
		retainDigests = append(retainDigests, digestStr)
	}

	retainCandidates := candidates
	rules := p.getUntaggedRules(*policy.KeepUntagged)
	if len(rules) == 0 {
		return nil
	}

	rulesCandidates := make([]*types.Candidate, 0)

	for _, rule := range rules {
		if zcommon.IsContextDone(ctx) {
			return nil
		}

		ruleCandidates := rule.Perform(retainCandidates)

		rulesCandidates = append(rulesCandidates, ruleCandidates...)
	}

	retainCandidates = rulesCandidates

	for _, retainCandidate := range retainCandidates {
		if _, ok := retainDigestsSet[retainCandidate.DigestStr]; !ok {
			reason := fmt.Sprintf(retainedStrFormat, retainCandidate.RetainedBy)

			logDigestAction(repo, "keep", reason, retainCandidate, p.config.DryRun, &p.log)

			retainDigestsSet[retainCandidate.DigestStr] = struct{}{}
			retainDigests = append(retainDigests, retainCandidate.DigestStr)
		}
	}

	for _, candidateInfo := range candidates {
		if _, ok := retainDigestsSet[candidateInfo.DigestStr]; !ok {
			logDigestAction(repo, "delete", filteredByUntaggedRules, candidateInfo, p.config.DryRun, &p.log)

			if p.auditLog != nil {
				logDigestAction(repo, "delete", filteredByUntaggedRules, candidateInfo, p.config.DryRun, p.auditLog)
			}
		}
	}

	return retainDigests
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

func logDigestAction(repo, decision, reason string, candidate *types.Candidate, dryRun bool, log *zlog.Logger) {
	log.Info().Str("module", "retention").
		Bool("dry-run", dryRun).
		Str("repository", repo).
		Str("mediaType", candidate.MediaType).
		Str("digest", candidate.DigestStr).
		Str("reference", candidate.DigestStr).
		Str("lastPullTimestamp", candidate.PullTimestamp.String()).
		Str("pushTimestamp", candidate.PushTimestamp.String()).
		Str("decision", decision).
		Str("reason", reason).Msg("applied untagged policy")
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
