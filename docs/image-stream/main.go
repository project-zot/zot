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
// If the client connection is lost, the channel is de-registered but the BlobStreamer continues.
type InFlightImageCopier struct {
	numChunksCopied int
	source          *BlobStreamer
	dest            io.Writer
	sync.Mutex
}

func NewInFlightImageCopier(source *BlobStreamer, dest io.Writer) *InFlightImageCopier {
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

// BlobStreamer (renamed from ChunkedImageCopier) is a writer to a temp location with many readers (clients).
// It splits a blob into chunks based on chunkSize and copies chunks to a temporary disk location.
// The latest chunk number is announced to channels of subscribers.
// Multiple clients can read from the temp file as chunks become available.
// Once fully downloaded and verified, the blob would be copied to actual repository storage.
type BlobStreamer struct {
	numChunksTotal  int
	numChunksOnDisk int

	onDiskPath      string
	inFlightReader  io.Reader
	clientMu        sync.Mutex
	clients         map[int]chan int
	numClientsTotal int
}

func NewBlobStreamer(destFilePath string, r io.Reader, numChunksTotal int) *BlobStreamer {
	return &BlobStreamer{
		numChunksTotal: numChunksTotal,
		onDiskPath:     destFilePath,
		inFlightReader: r,
		clients:        make(map[int]chan int),
	}
}

// Everytime a new client is interested in the current blob, the client would create a subscription
// here with a channel where latest chunk info is sent.
func (bs *BlobStreamer) Subscribe(channel chan int) int {
	bs.clientMu.Lock()
	defer bs.clientMu.Unlock()

	bs.clients[bs.numClientsTotal] = channel
	chanId := bs.numClientsTotal
	bs.numClientsTotal++

	// Announce the current number of available chunks
	// TODO: should probably use a mutex lock here.
	go func() {
		channel <- bs.numChunksOnDisk
	}()

	return chanId
}

func (bs *BlobStreamer) Unsubscribe(id int) {
	bs.clientMu.Lock()
	defer bs.clientMu.Unlock()

	delete(bs.clients, id)
}

// Starts writing content from inFlightReader to disk while updating clients
// Continues even if clients disconnect to avoid wasting partial work
func (bs *BlobStreamer) Transfer() {
	log.Println("starting writer")
	outputFile, err := os.OpenFile(bs.onDiskPath, os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		log.Printf("failed to open write file: %s\n", err.Error())
		os.Exit(1)
	}
	defer outputFile.Close()

	var wg sync.WaitGroup

	for bs.numChunksOnDisk < bs.numChunksTotal {
		// simulates writing network resp body into a blob file with delay
		_, err = io.CopyN(outputFile, bs.inFlightReader, chunkSizeBytes)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("failed to copy bytes: %s\n", err.Error())
				os.Exit(1)
			}
		}

		bs.numChunksOnDisk++
		bs.clientMu.Lock()

		// Update all clients about the new chunk
		// Clients always read the chunk from disk
		for _, c := range bs.clients {
			wg.Go(func() {
				c <- bs.numChunksOnDisk
			})
		}

		bs.clientMu.Unlock()
	}

	wg.Wait()
	log.Println("closing writer")
	// In actual implementation, after this point:
	// 1. Verify blob digest
	// 2. Copy from temp location to actual repository storage
	// 3. Clean up temp file
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

	// BlobStreamer writes to a temp location (ondiskblob.txt represents temp storage)
	blobStreamer := NewBlobStreamer("ondiskblob.txt", r, chunkCountForBuffer(buff))

	// client1.txt simulates an HTTP client receiving data over the network
	client1File, err := os.OpenFile("client1.txt", os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		log.Printf("failed to open client file: %s\n", err.Error())
		os.Exit(1)
	}

	client1 := NewInFlightImageCopier(blobStreamer, client1File)

	// stdout is also used as a client and simulates another client interested in the same blob
	client2 := NewInFlightImageCopier(blobStreamer, os.Stdout)

	var wg sync.WaitGroup

	// Simulates the network transfer starting first (BlobStreamer downloading from upstream)
	wg.Go(blobStreamer.Transfer)

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
