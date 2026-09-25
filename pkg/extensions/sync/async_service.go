//go:build sync

package sync

func (service *BaseService) IsAsyncOnDemandForRepo(repo string) bool {
	if !service.config.IsAsyncOnDemandEnabled() {
		return false
	}

	if len(service.config.Content) == 0 {
		return true
	}

	return service.contentManager.GetContentByLocalRepo(repo) != nil
}
