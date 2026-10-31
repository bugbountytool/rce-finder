module github.com/bugbountytool/rce-finder

go 1.22

require (
	github.com/google/uuid v1.6.0
	gopkg.in/yaml.v3 v3.0.1
)

replace gopkg.in/yaml.v3 => ./third_party/yaml.v3
