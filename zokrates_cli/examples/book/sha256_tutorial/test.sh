#!/bin/bash
set -e

alias zokrates=$1

zokrates compile -i hashexample.zok
zokrates compute-witness -a 0 0 0 5

grep '~out' witness

cp -f hashexample_updated.zok hashexample.zok

zokrates compile -i hashexample.zok
zokrates setup
zokrates export-verifier
zokrates compute-witness -a 0 0 0 5
zokrates generate-proof