#! /bin/bash

DIRS=("microcorruption_tutorial" "microcorruption_new_orleans" "microcorruption_sydney")

for DIR in "${DIRS[@]}"; do
	python convert_microcorruption.py "$DIR/micro.s" "$DIR/processed.s" "$DIR/out.elf"
done
