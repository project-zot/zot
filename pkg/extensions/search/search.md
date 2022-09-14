# `search`

`search` component provides efficient and enhanced registry search capabilities using graphQL backend.

| Supported queries | Input | Ouput | Description | graphQL query |
| --- | --- | --- | --- | --- |
| [Search images by digest](#search-images-by-digest) | digest | image list | Search all repositories in the registry and return list of images that matches given digest (manifest, config or layers) | ImageListForDigest |
| [Search images affected by a given CVE id](#search-images-affected-by-a-given-cve-id) | CVE id | image list | Search the entire registry and return list of images affected by given CVE | ImagesListForCVE |
| [List CVEs for a given image](#list-cves-of-given-image) | image | CVE list | Scan given image and return list of CVEs affecting the image | CVEListForImage |
| [List images not affected by a given CVE id](#list-images-not-affected-by-a-given-cve-id) | repository, CVE id | image list | Scan all images in a given repository and return list of latest (by date) images not affected by the given CVE |ImagesListWithCVEFixed|
| [List the latest image across every repository](#list-the-latest-image-across-every-repository) | \<none\> | image list | Search entire registry and return a list containing the latest (by date) image in each repository | ImageListWithLatestTag |
| [List all images with expanded information for a given repository](#list-all-images-with-expanded-information-for-a-given-repository) | repository | image list | List expanded image information for all images (including manifest, all layers, etc) in a given repository | ExpandedRepoInfo |

# Search images by digest

**Sample request**

```
curl -X POST -H "Content-Type: application/json" --data '{ "query": "{ ImageListForDigest (id:\"63a795ca90aa6e7cca60941e826810a4cd0a2e73ea02bf458241df2a5c973e29\") { Name Tags } }" }' http://localhost:8080/v2/_zot/ext/search
```

**Sample response**

```
	{
		"data": {
			"ImageListForDigest": [{
				"Name": "centos",
				"Tags": ["8"]
			}, {
				"Name": "v2/centos",
				"Tags": ["8"]
			}]
		}
	}
```

# Search images affected by a given CVE id

**Sample request**

```
curl -X POST -H "Content-Type: application/json" --data '{ "query": "{ ImageListForCVE (id:\"CVE-2002-1119\") { Name Tags } }" }' http://localhost:8080/v2/_zot/ext/search
```

**Sample response**

```
{
	"data": {
		"ImageListForCVE": [{
			"Name": "centos",
			"Tags": ["8"]
		}, {
			"Name": "v2/centos",
			"Tags": ["7", "8"]
		}]
	}
}
```
# List CVEs of given image

**Sample reques**t


```
curl -X POST -H "Content-Type: application/json" --data '{ "query": "{ CVEListForImage (image:\"centos\" ) { Tag CVEList { Id Title Description Severity PackageList {Name InstalledVersion FixedVersion } } } }" }' http://localhost:8080/v2/_zot/ext/search
```

**Sample response**

```
{
	"data": {
		"CVEListForImage": {
			"Tag": "",
			"CVEList": [{
				"Id": "CVE-2021-3712",
				"Title": "openssl: Read buffer overruns processing ASN.1 strings",
				"Description": "ASN.1 strings are represented internally within OpenSSL as an ASN1_STRING structure which contains a buffer. Fixed in OpenSSL 1.1.1l (Affected 1.1.1-1.1.1k). Fixed in OpenSSL 1.0.2za (Affected 1.0.2-1.0.2y).",
				"Severity": "MEDIUM",
				"PackageList": [{
					"Name": "openssl-libs",
					"InstalledVersion": "1:1.1.1g-11.el8",
					"FixedVersion": "1:1.1.1k-5.el8_5"
				}]
			}]
			}
		}
	}
```
# List images not affected by a given CVE id

**Sample request**

```
curl -X POST -H "Content-Type: application/json" --data '{ "query": "{ ImageListWithCVEFixed (id:\"CVE-2021-3713\",image:\"centos\") { Tags {Name Digest Timestamp} } }" }' http://localhost:8080/v2/_zot/ext/search
```

**Sample response**

```
{
	"data": {
		"ImageListWithCVEFixed": {
			"Tags": [{
				"Name": "8",
				"Digest": "sha256:63a795ca90aa6e7cca60941e826810a4cd0a2e73ea02bf458241df2a5c973e29",
				"Timestamp": "2020-12-08T00:22:52.526672082Z"
			}]
		}
	}
}
```

# List the latest image across every repository

**Sample request**

```
curl -X POST -H "Content-Type: application/json" --data '{ "query": "{ ImageListWithLatestTag () { Name Latest LastUpdated Description Licenses Vendor Size Labels} }" }' http://localhost:8080/v2/_zot/ext/search
```

**Sample response**

```
{
	"data": {
		"ImageListWithLatestTag": [{
			"Name": "centos",
			"Latest": "8",
			"LastUpdated": "2020-12-08T00:22:52.526672082Z",
			"Description": "",
			"Licenses": "GPLv2",
			"Vendor": "CentOS",
			"Size": "1074",
			"Labels": ""
		}, {
			"Name": "v2/centos",
			"Latest": "8",
			"LastUpdated": "2020-12-08T00:22:52.526672082Z",
			"Description": "",
			"Licenses": "GPLv2",
			"Vendor": "CentOS",
			"Size": "1074",
			"Labels": ""
		}]
	}
}
```

# List all images with expanded information for a given repository

Sample request

```
curl -X POST -H "Content-Type: application/json" --data '{ "query": "{ ExpandedRepoInfo (repo:\"v2/centos\") { Manifests {Digest Tag IsSigned Layers {Size Digest}}} }" }' http://localhost:8080/v2/_zot/ext/search
```

**Sample response**

```
{
	"data": {
		"ExpandedRepoInfo": {
			"Manifests": [{
				"Digest": "2bacca16b9df395fc855c14ccf50b12b58d35d468b8e7f25758aff90f89bf396",
				"Tag": "7",
				"IsSigned": false,
				"Layers": [{
					"Size": "76097157",
					"Digest": "2d473b07cdd5f0912cd6f1a703352c82b512407db6b05b43f2553732b55df3bc"
				}]
			}, {
				"Digest": "63a795ca90aa6e7cca60941e826810a4cd0a2e73ea02bf458241df2a5c973e29",
				"Tag": "8",
				"IsSigned": false,
				"Layers": [{
					"Size": "75181999",
					"Digest": "7a0437f04f83f084b7ed68ad9c4a4947e12fc4e1b006b38129bac89114ec3621"
				}]
			}]
		}
	}
}
```

