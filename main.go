package main

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Tormak9970/single-node-extractor/logger"
	"github.com/Tormak9970/single-node-extractor/reader"
	"github.com/Tormak9970/single-node-extractor/reader/hash"
	"github.com/Tormak9970/single-node-extractor/reader/tor"
)

//* build command: go build -o nodeExtractor.exe main.go

func zlipDecompress(buff []byte) ([]byte, error) {
	b := bytes.NewReader(buff)
	r, err := zlib.NewReader(b)

	if err != nil {
		fmt.Print(err)
		return nil, err
	}
	var out bytes.Buffer
	io.Copy(&out, r)

	return out.Bytes(), nil
}

func writeFile(data []byte, dir string, outputDir string) {
	if dir == "" {
		return
	}
	path := outputDir + "/" + dir

	destination, err := os.Create(path)
	logger.Check(err)

	destination.Write(data)
	destination.Close()
}

func fileNameToHash(name string) hash.FileId {
	return hash.FromFilePath(name, 0)
}

func readGOMString(reader reader.SWTORReader, offset uint64) string {
	var strBuff []byte
	oldOffset, _ := reader.Seek(0, 1)
	reader.Seek(int64(offset), 0)
	for true {
		tempBuff := make([]byte, 1)
		_, err := reader.File.Read(tempBuff)
		if err != nil {
			log.Panicln(err)
		}
		curChar := tempBuff[0]

		if curChar == 0 {
			break
		} else {
			strBuff = append(strBuff, curChar)
		}
	}
	reader.Seek(oldOffset, 0)
	return string(strBuff)
}

func main() {
	torFile := ""
	outputDir := ""
	nodeName := ""
	if len(os.Args) >= 4 {
		torFile = os.Args[1]
		outputDir = os.Args[2]
		nodeName = os.Args[3]
	}
	if torFile == "" || outputDir == "" || nodeName == "" {
		return
	}

	filesAttempted := 0
	filesNoHash := 0

	found := false

	data := tor.Read(torFile)

	start := time.Now()
	f, err := os.Open(torFile)
	defer f.Close()
	reader := reader.SWTORReader{File: f}
	if err != nil {
		log.Panicln(err)
	}

	for i := 0; i < 500; i++ { //500
		fileName := "/resources/systemgenerated/buckets/" + strconv.Itoa(i) + ".bkt"
		litHashes := hash.FromFilePath(fileName, 0)
		key := strconv.Itoa(int(litHashes.PH)) + "|" + strconv.Itoa(int(litHashes.SH))

		if data, ok := data[key]; ok {
			filesAttempted++

			oldPos, _ := reader.Seek(int64(data.Offset), 0)
			dblbOffset := data.Offset + uint64(data.HeaderSize) + 24

			reader.Seek(int64(dblbOffset), 0)
			dblbSize := reader.ReadUInt32()
			reader.ReadUInt32() //dblb header
			reader.ReadUInt32() //dblb version

			endOffset := data.Offset + uint64(data.HeaderSize) + 28 + uint64(dblbSize)

			var j int
			for pos, _ := reader.Seek(0, 1); pos < int64(endOffset); j++ {
				nodeOffset, _ := reader.Seek(0, 1)
				nodeSize := reader.ReadUInt32()
				if nodeSize == 0 {
					break
				}
				reader.ReadUInt32()
				reader.ReadUInt32() //idLo
				reader.ReadUInt32() //idHi

				reader.ReadUInt16() //type
				dataOffset := reader.ReadUInt16()

				nameOffset := reader.ReadUInt16()
				gomName := readGOMString(reader, uint64(nodeOffset)+uint64(nameOffset))
				if gomName == nodeName {
					found = true
					outputName := strings.ReplaceAll(gomName, "/", "") + ".node"

					reader.Seek(nodeOffset+int64(dataOffset), 0)

					buff := make([]byte, nodeSize-uint32(dataOffset))
					_, err := f.Read(buff)
					logger.Check(err)

					fileData, err2 := zlipDecompress(buff)
					logger.Check(err2)

					writeFile(fileData, outputName, outputDir)
					break
				}
				reader.Seek(nodeOffset+((int64(nodeSize)+7)&-8), 0)
			}

			reader.Seek(oldPos, 0)
			fmt.Println(filesAttempted, 500)
			if found {
				break
			}
		} else {
			filesNoHash++
		}
	}

	diff := time.Now().Sub(start)
	log.Println("duration", fmt.Sprintf("%s", diff))
	if found {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}
