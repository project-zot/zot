# `search` 

`search` component provides efficient and enhanced registry search capabilities using graphQL backend.

| Supported queries | Input | Ouput | Description | graphQL query |
| --- | --- | --- | --- | --- |
| [List CVEs for a given image](#list-cves-of-given-image) | image | CVE list | Scan given image and return list of CVEs affecting the image | CVEListForImage |
| [Search images affected by a given CVE id](#search-images-affected-by-a-given-cve-id) | CVE id | image list | Search the entire registry and return list of images affected by given CVE | ImagesListForCVE |
| [List images not affected by a given CVE id](#list-images-not-affected-by-a-given-cve-id) | repository, CVE id | image list | Scan all images in a given repository and return list of latest (by date) images not affected by the given CVE |ImagesListWithCVEFixed|
| [Search images by digest](#search-images-by-digest) | digest | image list | Search all repositories in the registry and return list of images that matches given digest (manifest, config or layers) | ImageListForDigest |
| [Latest image from all repos](#list-the-latest-image-across-every-repository) | none | repo summary list | Return the latest image from all the repos in the registry | RepoListWithNewestImage |
| [All images in repo](#all-images-in-repo) | repository | image list | Returns all images in the specified repo | ImageList |
| [List all images with expanded information for a given repository](#list-all-images-with-expanded-information-for-a-given-repository) | repository | repo info | List expanded repo information for all images in repo, alongisde a repo summary | ExpandedRepoInfo |
| [Global search](#global-search) | query | image summary / repo summary / layer summary | Will return what's requested in the query argument | GlobalSearch |
| [Derived image list](#search-derived-images) | image | image list | Returns a list of images that depend on the image specified in the arg | DerivedImageList |
| [Base image list](#search-base-images) | image | image list | Returns a list of images that the specified image depends on | BaseImageList |
| [Image](#search-image) | image | image summary | Returns details about a specific image | Image |

The exmaples below only include the GraphQL query without any additional details on how to send them to a server. They were made with the GraphQL playground from the debug binary. You can also use curl to make these queries, here's an example:

```
curl -X POST -H "Content-Type: application/json" --data '{ "query": "{ ImageListForCVE (id:\"CVE-2002-1119\") { Name Tags } }" }' http://localhost:8080/v2/_zot/ext/search
```

# List CVEs of given image

**Sample request**


```
{
  CVEListForImage(image: "centos:8") {
    Tag
    CVEList {
      Id
      Title
      Description
      Severity
      PackageList {
        Name
        InstalledVersion
        FixedVersion
      }
    }
  }
}
```

**Sample response**

```
{
  "data": {
    "CVEListForImage": {
      "Tag": "8",
      "CVEList": [
        {
          "Id": "CVE-2017-14166",
          "Title": "libarchive: Heap-based buffer over-read in the atol8 function",
          "Description": "libarchive 3.3.2 allows remote attackers to cause a denial of service (xml_data heap-based buffer over-read and application crash) via a crafted xar archive, related to the mishandling of empty strings in the atol8 function in archive_read_support_format_xar.c.",
          "Severity": "LOW",
          "PackageList": [
            {
              "Name": "libarchive",
              "InstalledVersion": "3.3.3-1.el8",
              "FixedVersion": "Not Specified"
            }
          ]
        }
}
```
# Search images affected by a given CVE id

**Sample request**

```
{
  ImageListForCVE(id: "CVE-2018-20651") {
    RepoName
    Tag
    Digest
    ConfigDigest
    LastUpdated
    IsSigned
    Size
    Platform {
      Os
      Arch
    }
    Vendor
    Score
    DownloadCount
    Licenses
    Title
  }
}
```

**Sample response** 

``` 
{
  "data": {
    "ImageListForCVE": [
      {
        "RepoName": "centos",
        "Tag": "8",
        "Digest": "sha256:5f34d0bb0261d32d0b0bc91024b7d4e98d94b08a49615e08c8a5a65bc3a7e09f",
        "ConfigDigest": "sha256:8c1402b22ad6fd13394f8ad35e18802169366d77586de6606f35d11b709a08b6",
        "LastUpdated": "2021-09-15T18:20:05.184694267Z",
        "IsSigned": false,
        "Size": "83518086",
        "Platform": {
          "Os": "linux",
          "Arch": "amd64"
        },
        "Vendor": "CentOS",
        "Score": null,
        "DownloadCount": null,
        "Licenses": "GPLv2",
        "Title": "CentOS Base Image"
      }
    ]
  }
}
```


# List images not affected by a given CVE id

**Sample request** 

```
{
  ImageListWithCVEFixed(id: "CVE-2018-20651", image: "ubuntu") {
    RepoName
    Tag
    Digest
    ConfigDigest
    LastUpdated
  }
}
```

**Sample response** 

``` 
{
  "data": {
    "ImageListWithCVEFixed": [
      {
        "RepoName": "ubuntu",
        "Tag": "latest",
        "Digest": "sha256:650d596072ad45c6b74f4923e2cfea8158da2fb3a7b8dbb0b9ae4da3088d0591",
        "ConfigDigest": "sha256:88eef892e29d5b11be933f13424ef885644a6a6978924fedfb51ba555278fe74",
        "LastUpdated": "2022-10-25T01:53:41.769246372Z"
      }
    ]
  }
}
```

# Search images by digest

**Sample request**

```
{
  ImageListForDigest(
    id: "5f34d0bb0261d32d0b0bc91024b7d4e98d94b08a49615e08c8a5a65bc3a7e09f"
  ) {
    RepoName
    Tag
    Title
  }
}
```

**Sample response** 

```
{
  "data": {
    "ImageListForDigest": [
      {
        "RepoName": "centos",
        "Tag": "8",
        "Title": "CentOS Base Image"
      }
    ]
  }
}
```
# List the latest image across every repository

**Sample request** 

```
{
  RepoListWithNewestImage {
    Name
    LastUpdated
    Size
    Platforms {
      Os
      Arch
    }
    NewestImage {
      Digest
      Tag
    }
  }
}
```

**Sample response** 

``` 
{
  "data": {
    "RepoListWithNewestImage": [
      {
        "Name": "ubuntu",
        "LastUpdated": "2022-10-25T01:53:41.769246372Z",
        "Size": "30427302",
        "Platforms": [
          {
            "Os": "linux",
            "Arch": "amd64"
          }
        ],
        "NewestImage": {
          "Digest": "sha256:650d596072ad45c6b74f4923e2cfea8158da2fb3a7b8dbb0b9ae4da3088d0591",
          "Tag": "latest"
        }
      },
      {
        "Name": "centos",
        "LastUpdated": "2021-09-15T18:20:05.184694267Z",
        "Size": "83519510",
        "Platforms": [
          {
            "Os": "linux",
            "Arch": "amd64"
          }
        ],
        "NewestImage": {
          "Digest": "sha256:5f34d0bb0261d32d0b0bc91024b7d4e98d94b08a49615e08c8a5a65bc3a7e09f",
          "Tag": "8"
        }
      }
    ]
  }
}
```

# All images in repo

Sample request

```
{
  ImageList (repo: "ubuntu") {
    Tag
    Digest
    LastUpdated
    Size
  }
}
```

**Sample response**
```
{
  "data": {
    "ImageList": [
      {
        "Tag": "latest",
        "Digest": "sha256:650d596072ad45c6b74f4923e2cfea8158da2fb3a7b8dbb0b9ae4da3088d0591",
        "LastUpdated": "2022-10-25T01:53:41.769246372Z",
        "Size": "30426374"
      },
      {
        "Tag": "xenial",
        "Digest": "sha256:34de800b5da88feb7723a87ecbbf238afb63dbfe0c828838e26ac7458bef0ac5",
        "LastUpdated": "2021-08-31T01:21:30.672229355Z",
        "Size": "46499103"
      }
    ]
  }
}
```

# List all images with expanded information for a given repository

Sample request 

```
{
  ExpandedRepoInfo(repo: "ubuntu") {
    Images {
      Tag
      Digest
      
    }
    Summary {
      LastUpdated
      Size
      NewestImage {
        Tag
        LastUpdated
        Digest
      }
    }
  }
}
```

**Sample response** 

``` 
{
  "data": {
    "ExpandedRepoInfo": {
      "Images": [
        {
          "Tag": "xenial",
          "Digest": "sha256:34de800b5da88feb7723a87ecbbf238afb63dbfe0c828838e26ac7458bef0ac5"
        },
        {
          "Tag": "latest",
          "Digest": "sha256:650d596072ad45c6b74f4923e2cfea8158da2fb3a7b8dbb0b9ae4da3088d0591"
        }
      ],
      "Summary": {
        "LastUpdated": "2022-10-25T01:53:41.769246372Z",
        "Size": "76929691",
        "NewestImage": {
          "Tag": "latest",
          "LastUpdated": "2022-10-25T01:53:41.769246372Z",
          "Digest": "sha256:650d596072ad45c6b74f4923e2cfea8158da2fb3a7b8dbb0b9ae4da3088d0591"
        }
      }
    }
  }
}
```

# Global search

Sample request
```
{
  GlobalSearch(query: "ubuntu:latest") {
    Images {
      RepoName
      Tag
      LastUpdated
      Layers {
        Size
        Digest
      }
    }
  }
}
```

**Sample response**
```
{
  "data": {
    "GlobalSearch": {
      "Images": [
        {
          "RepoName": "ubuntu",
          "Tag": "latest",
          "LastUpdated": "2022-10-25T01:53:41.769246372Z",
          "Layers": [
            {
              "Size": "30426374",
              "Digest": "sha256:301a8b74f71f85f3a31e9c7e7fedd5b001ead5bcf895bc2911c1d260e06bd987"
            }
          ]
        }
      ]
    }
  }
}
```
Sample request
```
{
  GlobalSearch(query: "") {
    Repos {
      Name
    }
  }
}
```
**Sample response**
```
{
  "data": {
    "GlobalSearch": {
      "Repos": [
        {
          "Name": "centos"
        },
        {
          "Name": "ubuntu"
        }
      ]
    }
  }
}
```
# Search derived images
Sample query
```
{
  DerivedImageList (image: "ubuntu") {
    RepoName
    Tag
    LastUpdated
  }
}
```
**Sample response**
```
{
  "data": {
    "DerivedImageList": [
      {
        "RepoName": "mariadb",
        "Tag": "latest",
        "LastUpdated": "2022-10-18T14:56:33.1993083+03:00"
      },
      {
        "RepoName": "maven",
        "Tag": "latest",
        "LastUpdated": "2022-10-14T18:30:12.0929807+03:00"
      },
      {
        "RepoName": "tomcat",
        "Tag": "jre17",
        "LastUpdated": "2022-10-18T14:55:13.8303866+03:00"
      }
    ]
  }
}
```

# Search base images
Sample query
```
{
  BaseImageList (image: "mariadb") {
    RepoName
    Tag
    LastUpdated
  }
}
```

**Sample response**
```
{
  "data": {
    "BaseImageList": [
      {
        "RepoName": "mariadb",
        "Tag": "latest",
        "LastUpdated": "2022-10-18T14:56:33.1993083+03:00"
      },
      {
        "RepoName": "ubuntu",
        "Tag": "jammy",
        "LastUpdated": "2022-10-14T18:29:18.0325322+03:00"
      },
      {
        "RepoName": "ubuntu",
        "Tag": "latest",
        "LastUpdated": "2022-10-14T18:26:59.6707939+03:00"
      }
    ]
  }
}
```

# Search image
Sample query
```
{ 
  Image(image: "mariadb:latest") { 
    RepoName
    Tag
    LastUpdated
    Digest
    Description
  }
}
```

**Sample response**
```
{
  "data": {
    "Image": {
      "RepoName": "mariadb",
      "Tag": "latest",
      "LastUpdated": "2022-10-18T14:56:33.1993083+03:00",
      "Digest": "sha256:49a299f5c4b1af5bc2aa6cf8e50ab5bad85db4d0095745369acfc1934ece99d0",
      "Description": "MariaDB Server is a high performing open source relational database, forked from MySQL."
    }
  }
}
```


