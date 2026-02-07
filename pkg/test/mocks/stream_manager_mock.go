package mocks

import (
	"io"

	"github.com/regclient/regclient/types/blob"
)

type StreamManagerMock struct{}

func (msm *StreamManagerMock) ConnectClient(blobDigest string, writer io.Writer) error {
	return nil
}

func (msm *StreamManagerMock) StreamingBlobReader(reader *blob.BReader) (*blob.BReader, error) {
	return reader, nil
}
