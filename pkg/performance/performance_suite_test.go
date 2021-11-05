package performance //nolint:testpackage

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

var (
	// pushedImagesNames []string
	op                          skopeoOp
	serverConfigPath            string
	serverConfig                *ServerConfig
	measurementConfig           *MeasurementConfig
	measurementConfigPath       string
	singleImagePushTime         int
	parallelPushTime            int
	singleImageParallelPushTime int
	times                       int
)

func init() {
	flag.StringVar(&serverConfigPath, "server.config", "",
		"path to the server config file")
	flag.StringVar(&measurementConfigPath, "measurement.config", "",
		"path to the measurement config file")
}

func TestPerformance(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Performance Suite")
}

var _ = BeforeSuite(func() {
	err := os.MkdirAll("pulled_images", 0777)
	if err != nil {
		log.Fatalln("Error creating pulled_images dir!", err)
	}

	Expect(serverConfigPath).To(BeAnExistingFile(),
		"Invalid test suite argument. server.config should be an existing file.")

	serverConfig = LoadServerConfig(serverConfigPath)
	op = skopeoOp{
		serverConfig.Username,
		serverConfig.Password,
		serverConfig.Address,
		serverConfig.TlsVerify,
		serverConfig.Repo,
	}

	Expect(measurementConfigPath).To(BeAnExistingFile(),
		"Invalid test suite argument. measurement.config should be an existing file.")

	measurementConfig = LoadMeasurementConfig(measurementConfigPath)
	singleImagePushTime = measurementConfig.SingleImagePushTime
	parallelPushTime = measurementConfig.ParallelPushTime
	singleImageParallelPushTime = measurementConfig.SingleImageParallelPushTime
	times = measurementConfig.Times
})

var _ = AfterSuite(func() {
	err := os.RemoveAll("pulled_images")
	if err != nil {
		log.Fatalln("Error removing pulled_images dir!", err)
	}
})

var _ = Describe("Check Zot Performance", func() {
	Measure("Performance measuring - push", func(b Benchmarker) {
		runtime := b.Time("runtime", func() {
			imageName := "zot-tests-dummy-push"
			Expect(runPushCommand(op, imageName)).To(Equal(true))
			Expect(runDeleteCommand(op, imageName)).To(Equal(true))
		})
		Expect(runtime.Seconds()).To(BeNumerically("<", singleImagePushTime),
			"Push oprations shouldn't take too long!")
	}, times)

	Measure("Performance measuring - parallel push", func(b Benchmarker) {
		runtime := b.Time("runtime", func() {
			imageNameIdx := "zot-tests-parallel-images-dummy-%d"
			var commands []string
			var pushedImages []string

			for i := 1; i <= 5; i++ {
				imageName := fmt.Sprintf(imageNameIdx, i)
				pushedImages = append(pushedImages, imageName)
				arguments := setCopyCommand(op)

				arguments = setCommandVariables(op, arguments, imageName, imageName, true)
				commands = append(commands, strings.Join(arguments, " "))
			}

			Expect(runCommands(commands)).To(Equal(true))

			for _, imageName := range pushedImages {
				arguments := setDeleteCommand(op, imageName)
				commands = append(commands, strings.Join(arguments, " "))
			}

			Expect(runCommands(commands)).To(Equal(true))
		})

		Expect(runtime.Seconds()).To(BeNumerically("<", parallelPushTime),
			"Push oprations shouldn't take too long!")
	}, times)

	Measure("Performance measuring - push single image parallel", func(b Benchmarker) {
		runtime := b.Time("runtime", func() {
			imageName := "zot-tests-single-images-dummy"
			var commands []string

			for i := 1; i <= 5; i++ {
				arguments := setCopyCommand(op)
				arguments = setCommandVariables(op, arguments, imageName, imageName, true)
				commands = append(commands, strings.Join(arguments, " "))
			}

			Expect(runCommands(commands)).To(Equal(true))
		})

		Expect(runtime.Seconds()).To(BeNumerically("<", singleImageParallelPushTime),
			"Push and Pull oprations shouldn't take too long!")
	}, times)
})
