# `search`

`search` component provides efficient and enhanced registry search capabilities using graphQL backend.

| Supported queries | Input | Ouput | Description | graphQL query |
| --- | --- | --- | --- | --- |
| [Search images by digest](#search-images-by-digest) | digest | image list | Search all repositories in the registry and return list of images that matches given digest (manifest, config or layers) | ImageListForDigest |
| [Search images affected by a given CVE id](#search-images-affected-by-a-given-cve-id) | CVE id | image list | Search the entire registry and return list of images affected by given CVE | ImagesListForCVE |
| [List CVEs for a given image](#list-cves-of-given-image) | image | CVE list | Scan given image and return list of CVEs affecting the image | CVEListForImage |
| [List images not affected by a given CVE id](#list-images-not-affected-by-a-given-cve-id) | repository, CVE id | image list | Scan all images in a given repository and return list of latest (by date) images not affected by the given CVE |ImagesListWithCVEFixed|
| [Latest image from all repos](#list-the-latest-image-across-every-repository) | none | repo summary list | Return the latest image from all the repos in the registry | RepoListWithNewestImage |
| [List all images with expanded information for a given repository](#list-all-images-with-expanded-information-for-a-given-repository) | repository | repo info | List expanded repo information for all images in repo, alongisde a repo summary | ExpandedRepoInfo |
| [All images in repo](#all-images-in-repo) | repository | image list | Returns all images in the specified repo | ImageList |
| [Global search](#global-search) | query | image summary / repo summary / layer summary | Will return what's requested in the query argument | GlobalSearch |
| [Derived image list](#search-derived-images) | image | image list | Returns a list of images that depend on the image specified in the arg | DerivedImageList |
| [Base image list](#search-base-images) | image | image list | Returns a list of images that the specified image depends on | BaseImageList |
| [Get details of a specific image](#get-details-of-a-specific-image) | image | image summary | Returns details about a specific image | Image |
| [Get referrers of a specific image](#get-referrers-of-a-specific-image) | repo, digest, type | artifact manifests | Returns a list of artifacts of given type referring to a specific repo and digests | Referrers |

The examples below only include the GraphQL query without any additional details on how to send them to a server. They were made with the GraphQL playground from the debug binary. You can also use curl to make these queries, here's an example:

```bash
curl -X POST -H "Content-Type: application/json" --data '{ "query": "{ ImageListForCVE (id:\"CVE-2002-1119\") { Name Tags } }" }' http://localhost:8080/v2/_zot/ext/search
```

## List CVEs of given image

**Sample request**

```graphql
{
  CVEListForImage(image: "centos:8", requestedPage: {limit: 1, offset:1, sortBy: SEVERITY}) {
    Tag
    Page {
      TotalCount
      ItemCount
    }
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

```json
{
  "data": {
    "CVEListForImage": {
      "Tag": "8",
      "Page": {
        "TotalCount": 292,
        "ItemCount": 1
      },
      "CVEList": [
        {
          "Id": "CVE-2022-24407",
          "Title": "cyrus-sasl: failure to properly escape SQL input allows an attacker to execute arbitrary SQL commands",
          "Description": "In Cyrus SASL 2.1.17 through 2.1.27 before 2.1.28, plugins/sql.c does not escape the password for a SQL INSERT or UPDATE statement.",
          "Severity": "HIGH",
          "PackageList": [
            {
              "Name": "cyrus-sasl-lib",
              "InstalledVersion": "2.1.27-5.el8",
              "FixedVersion": "2.1.27-6.el8_5"
            }
          ]
        }
      ]
    }
  }
}
```

## Search images affected by a given CVE id

**Sample request**

```graphql
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

```json
{
  "data": {
    "ImageListForCVE": [
      {
        "RepoName": "centos",
        "Tag": "centos8",
        "Digest": "sha256:ac0dc62b48b7f683b49365fecef3b1f4d99fbd249b762e99f13f74938d85a6c8",
        "ConfigDigest": "sha256:98a5843635a2ccc7d72b269923a65721480de929f882143c6c0a0eb43f9a2869",
        "LastUpdated": "2022-10-17T16:36:09.1751694+03:00",
        "IsSigned": true,
        "Size": "83545800",
        "Platform": {
          "Os": "linux",
          "Arch": "amd64"
        },
        "Vendor": "[The CentOS Project](https://github.com/CentOS/sig-cloud-instance-images)\n",
        "Score": null,
        "DownloadCount": 0,
        "Licenses": "View [license information](https://www.centos.org/legal/) for the software contained in this image.",
        "Title": "centos"
      },
    ]
  }
}
```

## List images not affected by a given CVE id

**Sample request**

```graphql
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

```json
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

## Search images by digest

**Sample request**

```graphql
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

```json
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

## List the latest image across every repository

**Sample request**

```graphql
{
  RepoListWithNewestImage(requestedPage: {limit: 2, offset:0, sortBy: ALPHABETIC_ASC}) {
    Page {
      TotalCount
      ItemCount
    }
    Results {
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
}
```

**Sample response**

```json
{
  "data": {
    "RepoListWithNewestImage": {
      "Page": {
        "TotalCount": 30,
        "ItemCount": 2
      },
      "Results": [
        {
          "Name": "mariadb",
          "LastUpdated": "2022-10-18T14:56:33.1993083+03:00",
          "Size": "124116964",
          "Platforms": [
            {
              "Os": "linux",
              "Arch": "amd64"
            }
          ],
          "NewestImage": {
            "Digest": "sha256:49a299f5c4b1af5bc2aa6cf8e50ab5bad85db4d0095745369acfc1934ece99d0",
            "Tag": "latest"
          }
        },
        {
          "Name": "tomcat",
          "LastUpdated": "2022-10-18T14:55:13.8303866+03:00",
          "Size": "311658063",
          "Platforms": [
            {
              "Os": "linux",
              "Arch": "amd64"
            }
          ],
          "NewestImage": {
            "Digest": "sha256:bbc5a3912b568fbfb5912beaf25054f1f407c32a53acae29f19ad97485731a78",
            "Tag": "jre17"
          }
        }
      ]
    }
  }
}
```

## All images in repo

**Sample request**

```graphql
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

```json
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

## List all images with expanded information for a given repository

**Sample request**

```graphql
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

```json
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

## Global search

**Sample request**

```graphql
{
  GlobalSearch(query: "ubuntu:latest") {
    Page {
      ItemCount
      TotalCount
    }
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

```json
{
  "data": {
    "GlobalSearch": {
      "Page": {
        "ItemCount": 1,
        "TotalCount": 1
      },
      "Images": [
        {
          "RepoName": "ubuntu",
          "Tag": "latest",
          "LastUpdated": "2022-10-14T18:26:59.6707939+03:00",
          "Layers": [
            {
              "Size": "30428928",
              "Digest": "sha256:cf92e523b49ea3d1fae59f5f082437a5f96c244fda6697995920142ff31d59cf"
            }
          ]
        }
      ]
    }
  }
}
```

**Sample request**

```graphql
{
  GlobalSearch(query: "") {
    Repos {
      Name
    }
  }
}
```

**Sample response**

```json
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

## Search derived images

**Sample query**

```graphql
{
  DerivedImageList(image: "ubuntu:latest", requestedPage: {offset: 0, limit: 10}) {
    Page {
      TotalCount
      ItemCount
    }
    Results {
      RepoName
      Tag
      LastUpdated
    }
  }
}
```

**Sample response**

```json
{
  "data": {
    "DerivedImageList": {
      "Page": {
        "TotalCount": 9,
        "ItemCount": 9
      },
      "Results": [
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
          "Tag": "latest",
          "LastUpdated": "2022-10-18T14:50:09.7229959+03:00"
        },
        {
          "RepoName": "tomcat",
          "Tag": "jre17",
          "LastUpdated": "2022-10-18T14:55:13.8303866+03:00"
        },
        {
          "RepoName": "tomcat",
          "Tag": "jre17-temurin",
          "LastUpdated": "2022-10-18T14:54:46.4133521+03:00"
        },
        {
          "RepoName": "tomcat",
          "Tag": "jre17-temurin-jammy",
          "LastUpdated": "2022-10-18T14:51:12.235475+03:00"
        }
      ]
    }
  }
}
```

## Search base images

**Sample query**

```graphql
{
  BaseImageList(image: "mariadb:latest", requestedPage: {offset: 0, limit: 10}) {
    Page {
      TotalCount
      ItemCount
    }
    Results {
      RepoName
      Tag
      LastUpdated
    }
  }
}
```

**Sample response**

```json
{
  "data": {
    "BaseImageList": {
      "Page": {
        "TotalCount": 4,
        "ItemCount": 4
      },
      "Results": [
        {
          "RepoName": "ubuntu",
          "Tag": "jammy",
          "LastUpdated": "2022-10-14T18:29:18.0325322+03:00"
        },
        {
          "RepoName": "ubuntu",
          "Tag": "jammy-20221003",
          "LastUpdated": "2022-10-14T18:29:07.0004587+03:00"
        },
        {
          "RepoName": "ubuntu",
          "Tag": "latest",
          "LastUpdated": "2022-10-14T18:26:59.6707939+03:00"
        },
        {
          "RepoName": "ubuntu",
          "Tag": "rolling",
          "LastUpdated": "2022-10-14T18:27:21.2441356+03:00"
        }
      ]
    }
  }
}
```

## Get details of a specific image

**Sample query**

```graphql
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

```json
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

## Get referrers of a specific image

**Sample query**

```graphql
{
  Referrers(
    repo: "golang"
    digest: "sha256:fed08b0eaea00aab17f82ecbb78675919d216c72eea985581758191f694aeaf7"
    type: "application/vnd.example.icecream.v1"
  ) {
    MediaType
    ArtifactType
    Digest
    Annotations {
      Key
      Value
    }
  }
}
```

**Sample response**

```json
{
  "data": {
    "Referrers": [
      {
        "MediaType": "application/vnd.oci.artifact.manifest.v1+json",
        "ArtifactType": "application/vnd.example.icecream.v1",
        "Digest": "sha256:be7a3d01c35a2cf53c502e9dc50cdf36b15d9361c81c63bf319f1d5cbe44ab7c",
        "Annotations": [
          {
            "Key": "format",
            "Value": "oci"
          },
          {
            "Key": "demo",
            "Value": "true"
          }
        ]
      },
      {
        "MediaType": "application/vnd.oci.artifact.manifest.v1+json",
        "ArtifactType": "application/vnd.example.icecream.v1",
        "Digest": "sha256:d9ad22f41d9cb9797c134401416eee2a70446cee1a8eb76fc6b191f4320dade2",
        "Annotations": [
          {
            "Key": "demo",
            "Value": "true"
          },
          {
            "Key": "format",
            "Value": "oci"
          }
        ]
      }
    ]
  }
}
```
