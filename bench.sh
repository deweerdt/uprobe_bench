curpath=$(dirname $0)
( ${curpath}/observed $1 > log 2>&1 ) & ( sleep 10; sudo timeout 10 python ${curpath}/bpf.py ${curpath}/observed; sleep 10; killall observed )
cat log | ./summarize
