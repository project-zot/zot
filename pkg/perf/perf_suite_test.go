package perf_test

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"runtime"
	"sync"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"gopkg.in/resty.v1"
	. "zotregistry.io/zot/pkg/perf"
	. "zotregistry.io/zot/pkg/perf/images"
)

// nolint: gochecknoglobals
var (
	username                    string
	password                    string
	address                     string
	repo                        string
	serverConfigPath            string
	serverConfig                *ServerConfig
	measurementConfig           *MeasurementConfig
	measurementConfigPath       string
	singleImagePushTime         int
	singleImagePullTime         int
	parallelPushTime            int
	singleImageParallelPushTime int
	singleImageParallelPullTime int
	times                       int
	parallelImagesNumber        int
	numCPU                      int
)

// nolint: gochecknoinits
func init() {
	// Define the number of CPUs
	// flag.IntVar(numCPU, "cpu", runtime.NumCPU(), "number of CPUs")
	// numCPU = runtime.NumCPU()
	// Define flags
	flag.StringVar(&serverConfigPath, "server.config", "",
		"path to the server config file")
	flag.StringVar(&measurementConfigPath, "measurement.config", "",
		"path to the measurement config file")
}

func ReadConfig() {
	serverConfig = LoadServerConfig(serverConfigPath)
	username = serverConfig.Username
	password = serverConfig.Password
	address = serverConfig.Address
	repo = serverConfig.Repo

	measurementConfig = LoadMeasurementConfig(measurementConfigPath)
	singleImagePushTime = measurementConfig.SingleImagePushTime
	singleImagePullTime = measurementConfig.SingleImagePullTime
	parallelPushTime = measurementConfig.ParallelPushTime
	singleImageParallelPushTime = measurementConfig.SingleImageParallelPushTime
	singleImageParallelPullTime = measurementConfig.SingleImageParallelPullTime
	times = measurementConfig.Times
	parallelImagesNumber = measurementConfig.ParallelImagesNumber
}

func SetupFunc() {
	if err := CreateImages(parallelImagesNumber); err != nil {
		log.Fatalln("Error creating images!", err)
	}

	if err := os.MkdirAll("pulled_images", 0777); err != nil {
		log.Fatalln("Error creating pulled_images dir!", err)
	}
}

func CleanUpFunc() {
	repoURL := fmt.Sprintf("https://%s", path.Join(address, repo))

	_, err := resty.R().SetBasicAuth(username, password).Delete(repoURL)
	if err != nil {
		log.Fatalln("Error removing repository!", err)
	}

	if err = os.RemoveAll("pulled_images"); err != nil {
		log.Fatalln("Error removing pulled_images dir!", err)
	}

	if err := DeleteImages(parallelImagesNumber); err != nil {
		log.Fatalln("Error deleting images!", err)
	}
}

func TestPerf(t *testing.T) {
	_, errServer := os.Stat(serverConfigPath)
	_, errMeasure := os.Stat(measurementConfigPath)

	if errors.Is(errServer, os.ErrNotExist) && errors.Is(errMeasure, os.ErrNotExist) {
		t.Skip("Skip running! Check server_config.json and measurement_config.json files!")
	}

	ReadConfig()
	SetupFunc()

	RegisterFailHandler(Fail)
	RunSpecs(t, "Performance Suite")

	// clean up time...
	CleanUpFunc()
}

var _ = Describe("Check Zot Performance", func() {
	Measure("Performance measuring - push", func(b Benchmarker) {
		imageName := "zot-tests-dummy-push"

		runtime := b.Time("runtime", func() {
			Expect(PushImage(path.Join("images", imageName), username, password, address, repo, imageName)).To(BeNil())
		})
		Expect(runtime.Seconds()).To(BeNumerically("<", singleImagePushTime),
			"Push oprations shouldn't take too long!")
	}, times)

	Measure("Performance measuring - parallel push", func(b Benchmarker) {
		numCPU = runtime.NumCPU()
		runtime.GOMAXPROCS(numCPU)
		waitGroup := sync.WaitGroup{}
		imageNameIdx := "zot-tests-parallel-images-dummy-%d"
		runtime := b.Time("runtime", func() {
			waitGroup.Add(parallelImagesNumber)
			for i := 1; i <= parallelImagesNumber; i++ {
				go func(i int) {
					imageName := fmt.Sprintf(imageNameIdx, i)
					Expect(PushImage(path.Join("images", imageName), username, password, address, repo, imageName)).To(BeNil())

					waitGroup.Done()
				}(i)
			}
			waitGroup.Wait()
		})
		Expect(runtime.Seconds()).To(BeNumerically("<", parallelPushTime),
			"Push oprations shouldn't take too long!")
	}, times)

	Measure("Performance measuring - push single image parallel", func(b Benchmarker) {
		numCPU = runtime.NumCPU()
		runtime.GOMAXPROCS(numCPU)
		waitGroup := sync.WaitGroup{}
		imageName := "zot-tests-single-images-dummy"
		runtime := b.Time("runtime", func() {
			waitGroup.Add(parallelImagesNumber)
			for i := 1; i <= parallelImagesNumber; i++ {
				go func() {
					Expect(PushImage(path.Join("images", imageName), username, password, address, repo, imageName)).To(BeNil())

					waitGroup.Done()
				}()
			}
			waitGroup.Wait()
		})
		Expect(runtime.Seconds()).To(BeNumerically("<", singleImageParallelPushTime),
			"Push and Pull oprations shouldn't take too long!")
	}, times)

	// // Measure pull image performance
	// Context("Measure pull image performance", func() {
	// 	Measure("Performance measuring - pull", func(b Benchmarker) {
	// 		runtime := b.Time("runtime", func() {
	// 			Expect(RunCopy(op, pulledImageName, pulledImageName, false)).To(Equal(true))
	// 		})
	// 		Expect(runtime.Seconds()).To(BeNumerically("<", singleImagePullTime),
	// 			"Pull oprations shouldn't take too long!")

	// 		Expect(os.RemoveAll(fmt.Sprintf(destFormat, pulledImageName))).To(BeNil())
	// 	}, times)

	// 	Measure("Performance measuring - pull", func(b Benchmarker) {
	// 		var commands []string
	// 		var pulledImages []string

	// 		for i := 1; i <= 5; i++ {
	// 			arguments := SetCopyCommand(op)
	// 			arguments = SetCommandVariables(op, arguments, pulledImageName,
	// 				fmt.Sprintf("%s-%d", pulledImageName, i), false)
	// 			commands = append(commands, strings.Join(arguments, " "))
	// 			pulledImages = append(pulledImages, fmt.Sprintf("%s-%d", pulledImageName, i))
	// 		}

	// 		runtime := b.Time("runtime", func() {
	// 			Expect(RunCommands(commands)).To(Equal(true))
	// 		})

	// 		Expect(runtime.Seconds()).To(BeNumerically("<", singleImageParallelPullTime),
	// 			"Pull oprations shouldn't take too long!")

	// 		for _, image := range pulledImages {
	// 			Expect(os.RemoveAll(fmt.Sprintf(destFormat, image))).To(BeNil())
	// 		}
	// 	}, times)
	// })
})
