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
curl -X POST -H "Content-Type: application/json" --data '{ "query": "{ ImageListForCVE (id:\"CVE-2002-1119\") { Results { RepoName Tag } } }" }' http://localhost:8080/v2/_zot/ext/search
```

## List CVEs of given image

**Sample request**

```graphql
{
  CVEListForImage(
    image: "alpine:3.17"
    requestedPage: {limit: 1, offset:1, sortBy: SEVERITY}
  ) {
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
      "Tag": "3.17",
      "Page": {
        "TotalCount": 9,
        "ItemCount": 1
      },
      "CVEList": [
        {
          "Id": "CVE-2023-5363",
          "Title": "openssl: Incorrect cipher key and IV length processing",
          "Description": "Issue summary: A bug has been identified in the processing of key and\ninitialisation vector (IV) lengths.  This can lead to potential truncation\nor overruns during the initialisation of some symmetric ciphers.\n\nImpact summary: A truncation in the IV can result in non-uniqueness,\nwhich could result in loss of confidentiality for some cipher modes.\n\nWhen calling EVP_EncryptInit_ex2(), EVP_DecryptInit_ex2() or\nEVP_CipherInit_ex2() the provided OSSL_PARAM array is processed after\nthe key and IV have been established.  Any alterations to the key length,\nvia the \"keylen\" parameter or the IV length, via the \"ivlen\" parameter,\nwithin the OSSL_PARAM array will not take effect as intended, potentially\ncausing truncation or overreading of these values.  The following ciphers\nand cipher modes are impacted: RC2, RC4, RC5, CCM, GCM and OCB.\n\nFor the CCM, GCM and OCB cipher modes, truncation of the IV can result in\nloss of confidentiality.  For example, when following NIST's SP 800-38D\nsection 8.2.1 guidance for constructing a deterministic IV for AES in\nGCM mode, truncation of the counter portion could lead to IV reuse.\n\nBoth truncations and overruns of the key and overruns of the IV will\nproduce incorrect results and could, in some cases, trigger a memory\nexception.  However, these issues are not currently assessed as security\ncritical.\n\nChanging the key and/or IV lengths is not considered to be a common operation\nand the vulnerable API was recently introduced. Furthermore it is likely that\napplication developers will have spotted this problem during testing since\ndecryption would fail unless both peers in the communication were similarly\nvulnerable. For these reasons we expect the probability of an application being\nvulnerable to this to be quite low. However if an application is vulnerable then\nthis issue is considered very serious. For these reasons we have assessed this\nissue as Moderate severity overall.\n\nThe OpenSSL SSL/TLS implementation is not affected by this issue.\n\nThe OpenSSL 3.0 and 3.1 FIPS providers are not affected by this because\nthe issue lies outside of the FIPS provider boundary.\n\nOpenSSL 3.1 and 3.0 are vulnerable to this issue.",
          "Severity": "HIGH",
          "PackageList": [
            {
              "Name": "libcrypto3",
              "InstalledVersion": "3.0.8-r0",
              "FixedVersion": "3.0.12-r0"
            },
            {
              "Name": "libssl3",
              "InstalledVersion": "3.0.8-r0",
              "FixedVersion": "3.0.12-r0"
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
  ImageListForCVE(id: "CVE-2023-0464") {
    Results{
      RepoName
      Tag
      Digest
      LastUpdated
      IsSigned
      Size
      Vendor
      DownloadCount
      Licenses
      Title
      Manifests {
        Digest
        ConfigDigest
        Platform {
          Os
          Arch
        }
      }
    }
  }
}
```

**Sample response**

```json
{
  "data": {
    "ImageListForCVE": {
      "Results": [
        {
          "RepoName": "alpine",
          "Tag": "3.17",
          "Digest": "sha256:75bfe77c8d5a76b4421cfcebbd62a28ae70d10147578d0cda45820e99b0ef1d8",
          "LastUpdated": "2023-02-11T04:46:42.558343068Z",
          "IsSigned": true,
          "Size": "3375436",
          "Vendor": "",
          "DownloadCount": 0,
          "Licenses": "",
          "Title": "",
          "Manifests": [
            {
              "Digest": "sha256:75bfe77c8d5a76b4421cfcebbd62a28ae70d10147578d0cda45820e99b0ef1d8",
              "ConfigDigest": "sha256:6a2bcc1c7b4c9207f791a4512d7f2fa8fc2daeae58dbc51cb2797b05415f082a",
              "Platform": {
                "Os": "linux",
                "Arch": "amd64"
              }
            }
          ]
        },
      ]
    }
  }
}
```

## List images not affected by a given CVE id

**Sample request**

```graphql
{
  ImageListWithCVEFixed(id: "CVE-2023-0464", image: "ubuntu") {
    Results {
      RepoName
      Tag
      Digest
      LastUpdated
      Manifests {
        Digest
        ConfigDigest
      }
    }
  }
}
```

**Sample response**

```json
{
  "data": {
    "ImageListWithCVEFixed": {
      "Results": [
        {
          "RepoName": "ubuntu",
          "Tag": "kinetic",
          "Digest": "sha256:1ac35e499e330f6520e80e91b29a55ff298077211f5ed66aff5cb357cca4a28f",
          "LastUpdated": "2022-10-14T15:28:55.0263968Z",
          "Manifests": [
            {
              "Digest": "sha256:1ac35e499e330f6520e80e91b29a55ff298077211f5ed66aff5cb357cca4a28f",
              "ConfigDigest": "sha256:824c0269745923afceb9765ae24f5b331bb6fcf2a82f7eba98b3cfd543afb41e"
            }
          ]
        },
        {
          "RepoName": "ubuntu",
          "Tag": "kinetic-20220922",
          "Digest": "sha256:79eae04a0e32878fef3f8c5f901c32f6704c4a80b7f3fd9d89629e15867acfff",
          "LastUpdated": "2022-10-14T15:27:41.2144454Z",
          "Manifests": [
            {
              "Digest": "sha256:79eae04a0e32878fef3f8c5f901c32f6704c4a80b7f3fd9d89629e15867acfff",
              "ConfigDigest": "sha256:15c8dcf63970bb14ea36e41aa001b87d8d31e25a082bf6f659d12489d3e53d90"
            }
          ]
        }
      ]
    }
  }
}
```

## Search images by digest

**Sample request**

```graphql
{
  ImageListForDigest(
    id: "79eae04a0e32878fef3f8c5f901c32f6704c4a80b7f3fd9d89629e15867acfff"
  ) {
    Results{
      RepoName
      Tag
      Title
    }
  }
}
```

**Sample response**

```json
{
  "data": {
    "ImageListForDigest": {
      "Results": [
        {
          "RepoName": "ubuntu",
          "Tag": "kinetic-20220922",
          "Title": "ubuntu"
        }
      ]
    }
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
    Results {
      Tag
      Digest
      LastUpdated
      Size
    }
  }
}
```

**Sample response**

```json
{
  "data": {
    "ImageList": {
      "Results": [
        {
          "Tag": "jammy",
          "Digest": "sha256:f96fcb040c7ee00c037c758cf0ab40638e6ee89b03a9d639178fcbd0e7f96d27",
          "LastUpdated": "2022-10-14T15:29:18.0325322Z",
          "Size": "30472739"
        },
        {
          "Tag": "jammy-20221003",
          "Digest": "sha256:86681debca1719dff33f426a0f5c41792ebc52496c5d78a93b655b8b48fb71b2",
          "LastUpdated": "2022-10-14T15:29:07.0004587Z",
          "Size": "30472748"
        },
        {
          "Tag": "kinetic",
          "Digest": "sha256:1ac35e499e330f6520e80e91b29a55ff298077211f5ed66aff5cb357cca4a28f",
          "LastUpdated": "2022-10-14T15:28:55.0263968Z",
          "Size": "27498890"
        },
        {
          "Tag": "kinetic-20220922",
          "Digest": "sha256:79eae04a0e32878fef3f8c5f901c32f6704c4a80b7f3fd9d89629e15867acfff",
          "LastUpdated": "2022-10-14T15:27:41.2144454Z",
          "Size": "27498899"
        },
        {
          "Tag": "latest",
          "Digest": "sha256:9bc6d811431613bf2fd8bf3565b319af9998fc5c46304022b647c63e1165657c",
          "LastUpdated": "2022-10-14T15:26:59.6707939Z",
          "Size": "30472740"
        },
        {
          "Tag": "rolling",
          "Digest": "sha256:72e75626c5068b9d9a462c4fc80a29787d0cf61c8abc81bfd5ea69f6248d56fc",
          "LastUpdated": "2022-10-14T15:27:21.2441356Z",
          "Size": "30472741"
        }
      ]
    }
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
          "Tag": "jammy",
          "Digest": "sha256:f96fcb040c7ee00c037c758cf0ab40638e6ee89b03a9d639178fcbd0e7f96d27"
        },
        {
          "Tag": "jammy-20221003",
          "Digest": "sha256:86681debca1719dff33f426a0f5c41792ebc52496c5d78a93b655b8b48fb71b2"
        },
        {
          "Tag": "kinetic",
          "Digest": "sha256:1ac35e499e330f6520e80e91b29a55ff298077211f5ed66aff5cb357cca4a28f"
        },
        {
          "Tag": "kinetic-20220922",
          "Digest": "sha256:79eae04a0e32878fef3f8c5f901c32f6704c4a80b7f3fd9d89629e15867acfff"
        },
        {
          "Tag": "rolling",
          "Digest": "sha256:72e75626c5068b9d9a462c4fc80a29787d0cf61c8abc81bfd5ea69f6248d56fc"
        },
        {
          "Tag": "latest",
          "Digest": "sha256:9bc6d811431613bf2fd8bf3565b319af9998fc5c46304022b647c63e1165657c"
        }
      ],
      "Summary": {
        "LastUpdated": "2022-10-14T15:29:18.0325322Z",
        "Size": "58146896",
        "NewestImage": {
          "Tag": "jammy",
          "LastUpdated": "2022-10-14T15:29:18.0325322Z",
          "Digest": "sha256:f96fcb040c7ee00c037c758cf0ab40638e6ee89b03a9d639178fcbd0e7f96d27"
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
      Manifests {
        Digest
        Layers {
          Size
          Digest
        }
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
          "LastUpdated": "2022-10-14T15:26:59.6707939Z",
          "Manifests": [
            {
              "Digest": "sha256:9bc6d811431613bf2fd8bf3565b319af9998fc5c46304022b647c63e1165657c",
              "Layers": [
                {
                  "Size": "30428928",
                  "Digest": "sha256:cf92e523b49ea3d1fae59f5f082437a5f96c244fda6697995920142ff31d59cf"
                }
              ]
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
