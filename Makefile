all: telemtool

telemtool: *.go
	go build -o telemtool *.go
