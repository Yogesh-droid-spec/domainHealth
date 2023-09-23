# bimi-dns
> One stop solution for all BIMI Problems. This package includes fetching of bimi record, parsing the provided/fetched record, validation of BIMI record, generating a new BIMI record

# Install
	npm install --save bimi-dns
  
# Usage
### BIMI Generator
```javascript
const bimi = require('bimi-dns');

// Generator
var generateInputs = {
  v:'BIMI1' // check version tag
  l:'https://folderName.s3.amazonaws.com/logo/bimi/demo.svg' // logo requried for bimi
  a:'https://folderName.s3.amazonaws.com/cert/bimi/demo.crt' // certification requried for bimi
}

bimi.generate(generateInputs)
.then(record => {
  console.log(record); //v=BIMI1;l=https://folderName.s3.amazonaws.com/logo/bimi/demo.svg;a=https://folderName.s3.amazonaws.com/cert/bimi/demo.crt
})
.catch(err => {
  console.log(err);
});
```

### BIMI Fetcher
```javascript
const bimi = require('bimi-dns');

// Fetcher from DNS
bimi.fetch('github.com','default')
.then(record => {
  console.log(record);
})
.catch(err => {
  console.log(err);
});
```

### BIMI Parser
```javascript
const bimi = require('bimi-dns');

// BIMI Record parser
bimi.parse('v=DMARC1;l=https://folderName.s3.amazonaws.com/logo/bimi/demo.svg;a=https://folderName.s3.amazonaws.com/cert/bimi/demo.crt')
.then(record => {
  console.log(record); //{v:{description:'The v tag is required and represents the protocol version. An example is v=BIMI1',value:'BIMI1'},l:{description:'The l tag pertains to how logo are created and presented to BIMI users.'},a:{description:'The a tag pertains to how certificate are created and presented to BIMI users.'}}
})
.catch(err => {
  console.log(err);
});
```
