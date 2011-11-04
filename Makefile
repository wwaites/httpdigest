include $(GOROOT)/src/Make.inc

TARG=github.com/wwaites/httpdigest
GOFILES=auth.go client.go

include $(GOROOT)/src/Make.pkg
