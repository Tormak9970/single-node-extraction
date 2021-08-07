package tor

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync"

	"github.com/SWTOR-Slicers/tor-reader/logger"
	"github.com/SWTOR-Slicers/tor-reader/reader"
	"github.com/gammazero/workerpool"
)

var someMapMutex = sync.RWMutex{}

type torStruct struct {
	fileList map[string]TorFile
	mutex    sync.RWMutex
}

func (tor *torStruct) FileListAppend(key string, data TorFile) {
	tor.mutex.Lock()
	tor.fileList[key] = data
	tor.mutex.Unlock()
}

func ReadAll(torNames []string) map[string]TorFile {
	pool := workerpool.New(runtime.NumCPU())

	tor := torStruct{}

	for _, torName := range torNames {
		torName := torName

		pool.Submit(func() {
			read(torName, &tor)
		})
	}
	pool.StopWait()

	return tor.fileList
}

func Read(torName string) map[string]TorFile {
	tor := torStruct{}
	read(torName, &tor)
	return tor.fileList
}

func read(torName string, tor *torStruct) {
	if tor.fileList == nil {
		tor.fileList = map[string]TorFile{}
	}
	f, err := os.Open(torName)

	defer f.Close()
	logger.Check(err)
	reader := reader.SWTORReader{File: f}
	magicNumber := reader.ReadUInt32()

	if magicNumber != 0x50594D {
		fmt.Println("Not MYP File")
	}

	f.Seek(12, 0)

	fileTableOffset := reader.ReadUInt64()

	namedFiles := 0

	for fileTableOffset != 0 {
		f.Seek(int64(fileTableOffset), 0)
		numFiles := int32(reader.ReadUInt32())
		fileTableOffset = reader.ReadUInt64()
		namedFiles += int(numFiles)
		for i := int32(0); i < numFiles; i++ {
			//fmt.Println(i, numFiles)
			offset := reader.ReadUInt64()
			if offset == 0 {
				f.Seek(26, 1)
				continue
			}
			info := TorFile{}
			info.HeaderSize = reader.ReadUInt32()
			info.Offset = offset
			info.CompressedSize = reader.ReadUInt32()
			info.UnCompressedSize = reader.ReadUInt32()
			current_position, _ := f.Seek(0, 1)
			info.SecondaryHash = reader.ReadUInt32()
			info.PrimaryHash = reader.ReadUInt32()
			f.Seek(current_position, 0)
			info.FileID = reader.ReadUInt64()
			info.Checksum = reader.ReadUInt32()
			info.CompressionMethod = reader.ReadUInt16()
			info.CRC = info.Checksum
			info.TorFile = torName
			tor.FileListAppend(strconv.Itoa(int(info.PrimaryHash))+"|"+strconv.Itoa(int(info.SecondaryHash)), info)
		}
	}
}
