#! /bin/bash

DIRS=("tutorial" "new_orleans" "sydney" "hanoi" "cusco")

for DIR in "${DIRS[@]}"; do
	MICRODIR="microcorruption_$DIR"
	python convert_microcorruption.py "$MICRODIR/micro.s" "$MICRODIR/processed.s" "$MICRODIR/out.elf"
done
