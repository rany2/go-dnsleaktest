# go-dnsleaktest

Use DNS leak test from the command line. 

# How to use?

```
$ git clone https://github.com/rany2/go-textsynth.git
$ go build
$ ./go-dnsleaktest 
Testing 36/36

Test complete:
  1) 162.158.21.49 (No PTR) hosted by Cloudflare in Marseille, France
  2) 162.158.21.50 (No PTR) hosted by Cloudflare in Marseille, France
```

# Usage

```
Usage of go-dnsleaktest:
  -json-output
        return json output
  -num-runs int
        number of times to run the test (standard = 6; extended = 36) (default 36)
```

# Acknowledgements

Based on https://gist.github.com/Tugzrida/6fe83682157ead89875a76d065874973
