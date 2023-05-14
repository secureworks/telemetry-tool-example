all: telemtool

EXENAME=telemtool

${EXENAME}: *.go
	go build -o ${EXENAME} *.go

clean:
	rm -f ${EXENAME}