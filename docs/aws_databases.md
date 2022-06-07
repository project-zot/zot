# AWS Database Options

We store blob paths and identify them by the digest. That means that if we were to use a schema-based database, the schema would be pretty simple.

## DynamoDB 

noSQL, schemaless, simplest, might need the least refactoring, can store pretty much anything

Database type: Key-value
Best for: Mobile and web apps, gaming, IoT

Pros: fully managed and scalable, set the upper limit only
Cons:

Amazon DynamoDB is a fully-managed, NoSQL database that’s highly consistent and scalable. A key-value and document platform, DynamoDB is multi-region, multi-master, has built-in security, and backup and restore features. Serverless web applications, microservices and mobile backends will all benefit from DynamoDB.

With DynamoDB, users create database tables that can store and retrieve huge amounts of data; it then automatically distributes data and traffic across multiple servers to ensure maximum throughput.

## Others:

### MemoryDB for Redis

Pros: very fast
Cons: very expensive?

### DocumentDB 
Mainly for json documents, perhaps overkill for just some paths

Pros: similar to MongoDB
Cons: more hands-on than Dynamo, mainly used to store documents

Database type: Document
Best for: Content management, catalogs, user profiles

Amazon DocumentDB is a fast, fully managed document database service: a non-relational database built to store and query data as documents.

### Relational
Perhaps useless, as we only do key-value with BoltDB. Pretty strongly typed, they use schemas, unnecessary complexity
