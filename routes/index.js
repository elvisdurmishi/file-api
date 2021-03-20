var express = require('express');
var router = express.Router();
const multer = require('multer');
const path = require('path');
const nvt = require('node-virustotal');

const storage = multer.diskStorage({
  destination: './files',
  filename: (req, file, cb) => {
    return cb(null, `${file.originalname}`);
  },
});

const upload = multer({
  storage: storage,
});

router.get('/', function (req, res, next) {
  res.render('index', { title: 'Express' });
});

router.post('/upload', upload.single('myFile'), function (req, res, nex) {
  console.log(req.file.filename);
  const fs = require('fs');
  const VirusTotalApi = require('virustotal-api');
  const virusTotal = new VirusTotalApi(process.env.VIRUS_TOTAL_API);
  fs.readFile('./files/' + req.file.filename, (err, data) => {
    if (err) {
      console.log(`Cannot read file. ${err}`);
    } else {
      virusTotal
        .fileScan(data, req.file.filename)
        .then((response) => {
          let resource = response.resource;
          virusTotal.fileReport(resource).then((result) => {
            console.log(result);
            res.json(result);
          });
        })
        .catch((err) => console.log(`Scan failed. ${err}`));
    }
  });
});

router.post('/url/:website', function (req, res, next) {
  var url = req.params.website;
  const defaultTimedInstance = nvt.makeAPI();
  const theSameKey = defaultTimedInstance.setKey(process.env.VIRUS_TOTAL_API);
  const theSameObject = defaultTimedInstance.domainLookup(
    url,
    function (err, response) {
      if (err) {
        res.send(err);
      }
      res.send(response);
    }
  );
});

module.exports = router;
