## Configuration

Zot will use the database specified in the environment variable called ***ZOT_CACHEDB_TYPE***, or the one specified in the zot config file. If none specified, boltDB will be used. The current options are:

- boltdb (default)
- dynamodb

### DynamoDB config

You need to give values to the following environment vars (or set them in the zot config file):

- ZOT_DYNAMODB_ENDPOINT
- ZOT_DYNAMODB_TABLENAME
- AWS_REGION
- AWS_ACCESS_KEY_ID
- AWS_SECRET_ACCESS_KEY

While the absence of access key env vars won't trigger a panic, the others will, as the AWS SDK does not provide default values for them.