const path = require('path');
const rimraf = require('rimraf');
const fs = require('fs');

// Remove build folder
rimraf.sync(path.resolve('./build'));
console.log('Build folder deleted');
