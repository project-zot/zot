package api_test

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/scheduler"
	"zotregistry.dev/zot/v2/pkg/storage"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

func TestRunDedupeTasks(t *testing.T) {
	Convey("RunDedupeTasks starts the dedupe walk on every store", t, func() {
		walked := map[string]int{}

		store := func(name string) storageTypes.ImageStore {
			return mocks.MockedImageStore{
				RunDedupeBlobsFn: func(interval time.Duration, sch *scheduler.Scheduler) {
					walked[name]++
				},
			}
		}

		storeController := storage.StoreController{
			DefaultStore: store("default"),
			SubStore: map[string]storageTypes.ImageStore{
				"/a": store("a"),
				"/b": store("b"),
				// a route whose store failed to open is skipped
				"/c": nil,
			},
		}

		api.RunDedupeTasks(storeController, nil)

		So(walked, ShouldResemble, map[string]int{"default": 1, "a": 1, "b": 1})
	})
}
