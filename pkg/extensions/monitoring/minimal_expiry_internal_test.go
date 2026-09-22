//go:build !metrics

package monitoring

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestExpireRepoMetricsIgnoresUnlabeledRepoMetrics(t *testing.T) {
	Convey("A repo-labeled cache entry with no label values survives the sweep", t, func() {
		ms := &metricServer{
			cache: &MetricsInfo{
				Counters:  []*CounterValue{{Name: repoUploads}, {Name: repoUploads, LabelValues: []string{"stale-repo"}}},
				Summaries: []*SummaryValue{{Name: httpRepoLatencySeconds}},
			},
			touchedRepos:  map[string]struct{}{},
			previousRepos: map[string]struct{}{"stale-repo": {}},
		}

		ms.expireRepoMetrics()

		So(len(ms.cache.Counters), ShouldEqual, 1)
		So(ms.cache.Counters[0].LabelValues, ShouldBeEmpty)
		So(len(ms.cache.Summaries), ShouldEqual, 1)
	})
}
