package main

import (
	"errors"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

const chunkSizeBytes = 5

// The simulated Network Reader implements io.Reader with a delay
// It intentionally reads up to 5 bytes at a time with a 2 second sleep to simulate a very slow
// network copy.
// The data supplied in the buffer is a stand-in for image blob data being transferred over the network.
type simulatedNetworkReader struct {
	src     []byte
	current int
}

func NewSimulatedNetworkReader(src []byte) *simulatedNetworkReader {
	return &simulatedNetworkReader{
		src:     src,
		current: 0,
	}
}

func (snr *simulatedNetworkReader) Read(b []byte) (n int, err error) {
	time.Sleep(2 * time.Second)

	if snr.current >= len(snr.src) {
		return 0, io.EOF
	}

	bytesRead := 0

	for i := range 5 {
		if snr.current+i >= len(snr.src) {
			break
		}

		b[i] = snr.src[snr.current+i]
		bytesRead = i + 1
	}

	snr.current += bytesRead
	return bytesRead, nil
}

// InFlightImageCopier represents a client that wants to stream an image while it is being written to disk.
// The data is copied first from disk up to the latest chunk and further copies wait for an announcement
// over a channel when a new chunk has been written to disk.
type InFlightImageCopier struct {
	numChunksCopied int
	source          *ChunkedImageCopier
	dest            io.Writer
	sync.Mutex
}

func NewInFlightImageCopier(source *ChunkedImageCopier, dest io.Writer) *InFlightImageCopier {
	return &InFlightImageCopier{
		numChunksCopied: 0,
		source:          source,
		dest:            dest,
	}
}

func (ific *InFlightImageCopier) Copy() (err error) {
	inputFile, err := os.Open(ific.source.onDiskPath)
	if err != nil {
		log.Printf("failed to open read file: %s\n", err.Error())
		os.Exit(1)
	}
	defer inputFile.Close()

	// Register channel for latest chunk count updates
	chunkChan := make(chan int, 1)

	id := ific.source.Subscribe(chunkChan)

	for {
		latestChunkNum := <-chunkChan

		ific.Lock()
		if latestChunkNum <= ific.numChunksCopied {
			ific.Unlock()
			continue
		}

		_, err = io.CopyN(ific.dest, inputFile, (int64(latestChunkNum)-int64(ific.numChunksCopied))*chunkSizeBytes)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("failed disk copy: %s\n", err.Error())
				os.Exit(1)
			}
		}
		ific.numChunksCopied = latestChunkNum
		ific.Unlock()

		if latestChunkNum == ific.source.numChunksTotal {
			// transfer is complete
			break
		}
	}

	ific.source.Unsubscribe(id)
	close(chunkChan)

	return nil
}

// ChunkedImageCopier is a helper that splits an image into chunks based on chunkSize
// It then copies chunks to disk.
// The latest chunk number is announced to channels of subscribers.
type ChunkedImageCopier struct {
	numChunksTotal  int
	numChunksOnDisk int

	onDiskPath      string
	inFlightReader  io.Reader
	clientMu        sync.Mutex
	clients         map[int]chan int
	numClientsTotal int
}

func NewChunkedImageCopier(destFilePath string, r io.Reader, numChunksTotal int) *ChunkedImageCopier {
	return &ChunkedImageCopier{
		numChunksTotal: numChunksTotal,
		onDiskPath:     destFilePath,
		inFlightReader: r,
		clients:        make(map[int]chan int),
	}
}

// Everytime a new client is interested in the current blob, the client would create a subscription
// here with a channel where latest chunk info is sent.
func (cic *ChunkedImageCopier) Subscribe(channel chan int) int {
	cic.clientMu.Lock()
	defer cic.clientMu.Unlock()

	cic.clients[cic.numClientsTotal] = channel
	chanId := cic.numClientsTotal
	cic.numClientsTotal++

	// Announce the current number of available chunks
	// TODO: should probably use a mutex lock here.
	go func() {
		channel <- cic.numChunksOnDisk
	}()

	return chanId
}

func (cic *ChunkedImageCopier) Unsubscribe(id int) {
	cic.clientMu.Lock()
	defer cic.clientMu.Unlock()

	delete(cic.clients, id)
}

// Starts writing content from inFlightReader to disk while updating clients
func (cic *ChunkedImageCopier) Transfer() {
	log.Println("starting writer")
	outputFile, err := os.OpenFile(cic.onDiskPath, os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		log.Printf("failed to open write file: %s\n", err.Error())
		os.Exit(1)
	}
	defer outputFile.Close()

	var wg sync.WaitGroup

	for cic.numChunksOnDisk < cic.numChunksTotal {
		// simulates writing network resp body into a blob file with delay
		_, err = io.CopyN(outputFile, cic.inFlightReader, chunkSizeBytes)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("failed to copy bytes: %s\n", err.Error())
				os.Exit(1)
			}
		}

		cic.numChunksOnDisk++
		cic.clientMu.Lock()

		// Update all clients about the new chunk
		// Clients always read the chunk from disk
		for _, c := range cic.clients {
			wg.Go(func() {
				c <- cic.numChunksOnDisk
			})
		}

		cic.clientMu.Unlock()
	}

	wg.Wait()
	log.Println("closing writer")
}

func chunkCountForBuffer(b []byte) int {
	chunkCount := len(b) / chunkSizeBytes
	remainder := len(b) % chunkSizeBytes

	if remainder > 0 {
		chunkCount++
	}

	return chunkCount
}

func main() {
	// 104 bytes - represents a single image blob
	buff := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Duis consectetur pellentesque ultrices sit. S12")

	r := NewSimulatedNetworkReader(buff)

	msf := NewChunkedImageCopier("ondiskblob.txt", r, chunkCountForBuffer(buff))

	// client1.txt simulates an HTTP client receiving data over the network
	client1File, err := os.OpenFile("client1.txt", os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		log.Printf("failed to open client file: %s\n", err.Error())
		os.Exit(1)
	}

	client1 := NewInFlightImageCopier(msf, client1File)

	// stdout is also used as a client and simulates another client interested in the same blob
	client2 := NewInFlightImageCopier(msf, os.Stdout)

	var wg sync.WaitGroup

	// Simulates the network transfer starting first
	wg.Go(msf.Transfer)

	time.Sleep(10 * time.Millisecond)

	wg.Go(func() {
		err := client1.Copy()
		if err != nil {
			log.Printf("client1: failed to copy: %s\n", err.Error())
		}
	})

	// Wait for a bit longer to test a case where a new client comes in during the middle of copy
	time.Sleep(5 * time.Second)

	wg.Go(func() {
		err := client2.Copy()
		if err != nil {
			log.Printf("client2: failed to copy: %s\n", err.Error())
		}
	})

	wg.Wait()
}
