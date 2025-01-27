package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/scrypt"
)

const saltSize = 16

func main() {
	mode := flag.String("mode", "", "Mode: encrypt or decrypt")
	path := flag.String("path", "", "Path to file or directory")
	flag.Parse()

	if *mode == "" || *path == "" {
		fmt.Println("Usage: -mode <encrypt|decrypt> -path <file|directory> -password <password>")
		return
	}

	scanner := bufio.NewScanner(os.Stdin)

	fmt.Print("Enter password: ")
	scanner.Scan()
	password := scanner.Text()
	if len(password) < 8 {
		panic(errors.New("too easy password"))
	}

	var err error
	if *mode == "encrypt" {
		err = processFiles(*path, []byte(password), *mode, EncryptFile)
	} else if *mode == "decrypt" {
		err = processFiles(*path, []byte(password), *mode, DecryptFile)
	} else {
		fmt.Println("Invalid mode. Use 'encrypt' or 'decrypt'.")
		return
	}

	if err != nil {
		fmt.Println("Error:", err)
	}
}

func processFiles(path string, password []byte, mode string, processFunc func([]byte, *os.File) error) error {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return err
	}

	if fileInfo.IsDir() {
		return filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && (mode == "decrypt" && filepath.Ext(filePath) == ".enc" || mode == "encrypt") {
				file, err := os.OpenFile(filePath, os.O_RDONLY, 0666)
				if err != nil {
					return err
				}
				defer file.Close()
				return processFunc(password, file)
			}
			return nil
		})
	} else {
		if mode == "decrypt" && filepath.Ext(path) == ".enc" || mode == "encrypt" {
			file, err := os.OpenFile(path, os.O_RDONLY, 0666)
			if err != nil {
				return err
			}
			defer file.Close()
			return processFunc(password, file)
		} else {
			return errors.New("invalid mode")
		}
	}
}

func genKey(password []byte, salt []byte) ([32]byte, error) {
	keyLenght := 32
	key, errKey := scrypt.Key(password, salt, 32768, 8, 1, keyLenght)
	return [32]byte(key), errKey

}

func EncryptFile(password []byte, src *os.File) error {
	stat, _ := src.Stat()
	fileNameReader := bytes.NewBufferString(stat.Name())
	if fileNameReader.Len() > 255 {
		return errors.New("file name too large")
	}
	fileNameLenReader := bytes.NewBuffer([]byte{byte(fileNameReader.Len())})
	sourceReader := bufio.NewReader(src)

	salt := [16]byte{}
	rand.Read(salt[:])

	key, err := genKey(password, salt[:])
	if err != nil {
		return errors.New("err generating key")
	}

	reader := io.MultiReader(fileNameLenReader, fileNameReader, sourceReader)

	cipherData, errEncrypt := encrypt(key, reader)
	if errEncrypt != nil {
		return errEncrypt
	}

	name := make([]byte, 8)
	rand.Read(name)
	newFile, errCreate := os.OpenFile(fmt.Sprintf("./%s.enc", hex.EncodeToString(name)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
	if errCreate != nil {
		return errCreate
	}
	defer newFile.Close()

	signatureReader, signatureWriter := io.Pipe()
	fileReader := io.TeeReader(cipherData, signatureWriter)

	go func() {
		newFile.Write(salt[:])
		blankSignature := [sha256.Size]byte{}
		newFile.Write(blankSignature[:])
		newFile.ReadFrom(fileReader)
		signatureWriter.Close()
	}()

	signature, errSignature := sing(key[:], signatureReader)
	if errSignature != nil {
		return errSignature
	}
	newFile.WriteAt(signature, saltSize)
	return nil
}

func DecryptFile(password []byte, src *os.File) error {
	readerSrc := bufio.NewReader(src)

	salt := [16]byte{}
	readerSrc.Read(salt[:])

	key, err := genKey(password, salt[:])
	if err != nil {
		return errors.New("err generating key")
	}

	ok, errVerifySignature := verifySignature(key[:], readerSrc)
	if errVerifySignature != nil {
		return errVerifySignature
	}
	if !ok {
		return errors.New("corrupted file")
	}

	stat, _ := src.Stat()
	fileSectionReader := io.NewSectionReader(src, saltSize+sha256.Size, stat.Size()-sha256.Size)
	fileReader := bufio.NewReader(fileSectionReader)

	plainData, errDecrypt := decrypt(key, fileReader)
	if errDecrypt != nil {
		return errDecrypt
	}

	fileNameSize := make([]byte, 1)
	plainData.Read(fileNameSize)
	fileName := make([]byte, fileNameSize[0])
	plainData.Read(fileName)

	newFile, errCreate := os.OpenFile(fmt.Sprintf("./%s", fileName), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
	if errCreate != nil {
		return errCreate
	}
	defer newFile.Close()

	newFile.ReadFrom(plainData)

	return nil
}

func encrypt(key [32]byte, input io.Reader) (io.Reader, error) {
	block, errNewCipher := aes.NewCipher(key[:])
	if errNewCipher != nil {
		return nil, errNewCipher
	}

	iv := make([]byte, block.BlockSize())
	_, errRead := rand.Read(iv)
	if errRead != nil {
		return nil, errRead
	}
	ivClone := bytes.Clone(iv)

	encripter := cipher.NewCTR(block, iv)

	reader, writer := io.Pipe()

	go func() {
		writer.Write(ivClone)
		stream := cipher.StreamWriter{S: encripter, W: writer}
		_, errCopy := io.Copy(stream, input)
		if errCopy != nil {
			panic(errCopy)
		}
		writer.Close()
	}()

	return reader, nil
}

func decrypt(key [32]byte, input io.Reader) (io.Reader, error) {
	block, errNewCipher := aes.NewCipher(key[:])
	if errNewCipher != nil {
		return nil, errNewCipher
	}

	iv := make([]byte, block.BlockSize())
	_, errRead := input.Read(iv)
	if errRead != nil {
		return nil, errRead
	}

	decripter := cipher.NewCTR(block, iv)

	reader, writer := io.Pipe()

	go func() {
		stream := cipher.StreamWriter{S: decripter, W: writer}
		_, errCopy := io.Copy(stream, input)
		if errCopy != nil {
			panic(errCopy)
		}
		writer.Close()
	}()

	return reader, nil
}

func sing(key []byte, data io.Reader) ([]byte, error) {
	hmac := hmac.New(sha256.New, key)
	_, errCopy := io.Copy(hmac, data)
	if errCopy != nil {
		return nil, errCopy
	}

	return hmac.Sum(nil), nil
}

func verifySignature(key []byte, data io.Reader) (bool, error) {
	signature := make([]byte, sha256.Size)
	data.Read(signature)

	calculatedSignature, errSing := sing(key, data)
	if errSing != nil {
		return false, errSing
	}
	ok := hmac.Equal(signature, calculatedSignature)
	return ok, nil
}
