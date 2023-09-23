var dns = require('dns');
var fetch = function (domainName,selector) {
	return new Promise((resolve, reject) => {
		dns.resolveTxt(`${selector}._bimi.` + domainName, (err, records) => {
			if (err) {
				if (err.message && typeof err.message == 'string' && err.message.startsWith('queryTxt ENOTFOUND'))
					return reject(new Error('BIMI Record not available'));
				return reject(err.message);
			}
			var record = null;
			for (var i = 0; i < records.length; i++) {
				for (var j = 0; j < records[i].length; j++) {
					if (records[i][j].startsWith('v=BIMI')) {
						record = records[i][j];
						break;
					}
				}
				if (record && records[i].length > 0) record = records[i].join("")
				if (record != null)
					break;
			}
			if (record == null) return reject(new Error('BIMI Record not available'));
			return resolve(record);
		});
	})
}

module.exports = fetch;