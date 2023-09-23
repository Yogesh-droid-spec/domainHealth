const express = require('express');
const router = express.Router();
const dns = require('dns');
const whois = require('whois-json');
const http = require('http');
const https = require('https');
const lookup = require('dnsbl-lookup');
const puppeteer = require('puppeteer');
const { google } = require('googleapis');
const fs = require('fs');
const stream = require('stream');
const { log } = require('console');




// Function to capture website screenshot 
// async function captureScreenshotAndUpload(url) {
//   try {
//     const browser = await puppeteer.launch({
//       headless:'new',
//       args:[
//           '--no-sandbox'
//       ]
//   });

//   const page = (await browser.pages())[0];
//   await page.goto(url,{timeout:5000});
//  const bs64 = await page.screenshot({ encoding:'base64' });
//   await browser.close()
//   return bs64;
//   } catch (error) {
//     console.error('Error capturing screenshot', error);
//     throw error;
//   }
// }

// Function to fetch BIMI record for a domain with error logging and a timeout
async function fetchBimiRecord(domain, timeoutMs = 5000) {
  return new Promise(async (resolve) => {
    const timer = setTimeout(() => {
      console.log('DNS query timed out for', domain);
      resolve([]);
    }, timeoutMs);

    try {
      const bimiRecord = await dns.promises.resolveTxt(`default._bimi.${domain}`);
      clearTimeout(timer);
      resolve(bimiRecord);
    } catch (error) {
      clearTimeout(timer);
      console.error('Error fetching BIMI Record for', domain, error.message);
      resolve([]);
    }
  });
}

async function checkDomainBlacklist(domain, blocklistArray) {
  return new Promise((resolve, reject) => {
    const uribl = new lookup.uribl([domain], blocklistArray);
    console.log("bye dosto!!");
    const result = {};

    uribl.on('error', function (err, bl) {
      console.error(`Error checking blocklist ${bl} for ${domain}: ${err}`);
    });

    uribl.on('data', function (response, bl) {
      result[bl] = response;
    });

    uribl.on('done', function () {
      resolve(result); // Resolve with the result when done
    });
  });
}



// Function to fetch DKIM records for a domain with a specific selector
async function fetchDkimRecords(domain, selector) {
  try {
    const dkimSubdomain = `${selector}._domainkey.${domain}`;
    const txtRecords = await dns.promises.resolveTxt(dkimSubdomain);

    // Filter and parse DKIM records (if multiple exist)
    const dkimRecords = txtRecords
      .filter(record => record[0].startsWith('v=DKIM1'))
      .map(record => {
        const keyValuePairs = record[0].split(';');
        const dkimRecord = {};

        for (const pair of keyValuePairs) {
          const [key, value] = pair.split('=');
          dkimRecord[key.trim()] = value.trim();
        }

        return dkimRecord;
      });

    return dkimRecords;
  } catch (error) {
    if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
      return []; // Return an empty array if DKIM records are not found (ENOTFOUND)
    } else {
      throw error; // Throw other DNS resolution errors
    }
  }
}

// Function to fetch DKIM records for a domain with a specific selector
async function fetchAllDkimRecords(domain, selector) {
  try {
    const dkimSubdomain = `${selector}._domainkey.${domain}`;
    const txtRecords = await dns.promises.resolveTxt(dkimSubdomain);

    // Filter and parse DKIM records (if multiple exist)
    const dkimRecords = txtRecords
      .map(record => {
        const dkimRecord = {};
        const keyValuePairs = record[0].split(';');

        for (const pair of keyValuePairs) {
          const [key, value] = pair.split('=');
          if (key && value) {
            dkimRecord[key.trim()] = value.trim();
          }
        }

        // Check if the necessary DKIM properties exist
        if (dkimRecord.v && dkimRecord.k) {
          return dkimRecord;
        }

        return null; // Skip records that don't have the required properties
      })
      .filter(record => record !== null);

    return dkimRecords;
  } catch (error) {
    if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
      return []; // Return an empty array if DKIM records are not found (ENOTFOUND)
    } else {
      throw error; // Throw other DNS resolution errors
    }
  }
}

// Function to fetch MX records for a domain
async function fetchMxRecords(domain) {
  try {
    const mxRecords = await dns.promises.resolveMx(domain);
    console.log("Hello dosto!!");
    return mxRecords;
  } catch (error) {
    if (error.code === 'ENODATA'||error.code==='ENOTFOUND') {
      return []; // Return an empty array if MX records are not found (ENOTFOUND)
    } else {
      throw error; // Throw other DNS resolution errors
    }
  }
}

// Function to fetch SPF records for a domain
async function fetchSpfRecords(domain) {
  try {
    const txtRecords = await dns.promises.resolveTxt(domain);
    const spfRecords = txtRecords.filter(record => record[0].startsWith('v=spf1'));
    return spfRecords;
  } catch (error) {
    if (error.code === 'ENODATA'||error.code==='ENOTFOUND') {
      return []; // Return an empty array if SPF records are not found (ENOTFOUND)
    } else {
      throw error; // Throw other DNS resolution errors
    }
  }
}

// Function to fetch DMARC records for a domain
async function fetchDmarcRecords(domain) {
  try {
    const dmarcSubdomain = '_dmarc.' + domain;
    const txtRecords = await dns.promises.resolveTxt(dmarcSubdomain);
    return txtRecords;
  } catch (error) {
    if (error.code === 'ENOTFOUND'||error.code==='ENODATA') {
      return []; // Return an empty array if DMARC records are not found (ENOTFOUND)
    } else {
      throw error; // Throw other DNS resolution errors
    }
  }
}

// Function to fetch common domain information (HTTP, HTTPS, TLS-RPT, etc.)
async function fetchCommonDomainInfo(domain) {
  try {
    const [httpSupported, httpsSupported, tlsRptRecords] = await Promise.all([
      checkHttpSupport(domain),
      checkHttpsSupport(domain),
      fetchTlsRptRecord(domain)
    ]);

    return {
      httpSupported,
      httpsSupported,
      tlsRptRecords
    };
  } catch (error) {
    throw error;
  }
}

// Function to check if HTTP is supported
function checkHttpSupport(domain) {
  return new Promise((resolve, reject) => {
    const requestOptions = {
      method: 'HEAD',
      hostname: domain,
      port: 80,
    };

    const req = http.request(requestOptions, (res) => {
      if (res.statusCode === 200) {
        resolve(true); // HTTP is supported
      } else {
        resolve(false); // HTTP is not supported or other status code
      }
    });

    req.on('error', (error) => {
      resolve(false); // HTTP connection failed
    });

    req.end();
  });
}

// Function to check if HTTPS is supported
function checkHttpsSupport(domain) {
  return new Promise((resolve, reject) => {
    const requestOptions = {
      method: 'HEAD',
      hostname: domain,
      port: 443,
    };

    const req = https.request(requestOptions, (res) => {
      if (res.statusCode === 200) {
        resolve(true); // HTTPS is supported
      } else {
        resolve(false); // HTTPS is not supported or other status code
      }
    });

    req.on('error', (error) => {
      resolve(false); // HTTPS connection failed
    });

    req.end();
  });
}

// Function to fetch TLS-RPT (TLS Reporting Policy and Trust) records for a domain
async function fetchTlsRptRecord(domain) {
  try {
    const tlsRptSubdomain = '_tlsrpt.' + domain;
    const records = await dns.promises.resolveTxt(tlsRptSubdomain);
    return records;
  } catch (error) {
    return [];
  }
}

// Function to fetch domain age and registrar information
async function fetchDomainInfo(domain) {
  try {
    const whoisData = await whois(domain);

    const creationDate = whoisData.creationDate;
    const registrar = whoisData.registrar;

    if (!creationDate || !registrar) {
      return {
        registrar:'',
        creationDate:'',
        ageInDays:''
      }
      throw new Error('Domain information not found.');
    }

    // Calculate domain age
    const currentDate = new Date();
    const ageInMilliseconds = currentDate - new Date(creationDate);
    const ageInDays = Math.floor(ageInMilliseconds / (1000 * 60 * 60 * 24));

    return {
      registrar: registrar,
      creationDate: creationDate,
      ageInDays: ageInDays
    };
  } catch (error) {
    throw error;
  }
}
// Function to perform a name server (NS) lookup for a domain
async function fetchNameServers(domain) {
  try {
    const nameServers = await new Promise((resolve, reject) => {
      dns.resolveNs(domain, (err, nsRecords) => {
        if (err) {
          
        } else {
          resolve(nsRecords);
        }
      });
    });
    return nameServers;
  } catch (error) {
    if (error.code === 'ENOTFOUND'||error.code==='ENODATA') {
      return []; 
    } else {
      throw error; 
    }
  }
}

// Function to fetch A (IPv4) records for a domain
async function fetchARecords(domain) {
  try {
    const addresses = await dns.promises.resolve4(domain);
    return addresses;
  } catch (error) {
    return [];
  }
}

// Function to fetch AAAA (IPv6) records for a domain
async function fetchAAAARecords(domain) {
  try {
    const addresses = await dns.promises.resolve6(domain);
    return addresses;
  } catch (error) {
    return [];
  }
}

// Function to discover specific subdomains for a domain
async function discoverSubdomains(domain) {
  const subdomainsToCheck = ['shop','www', 'mail', 'ftp', 'blog', 'test','status','link','remote']; // Add the subdomains you want to check here
  const discoveredSubdomains = [];

  for (const subdomain of subdomainsToCheck) {
    try {
      // Check A records
      const aSubdomain = `${subdomain}.${domain}`;
      const aRecords = await fetchARecords(aSubdomain);
      if (aRecords.length > 0 && !discoveredSubdomains.includes(aSubdomain)) {
        discoveredSubdomains.push(aSubdomain);
      }

      // Check AAAA records
      const aaaaSubdomain = `${subdomain}.${domain}`;
      const aaaaRecords = await fetchAAAARecords(aaaaSubdomain);
      if (aaaaRecords.length > 0 && !discoveredSubdomains.includes(aaaaSubdomain)) {
        discoveredSubdomains.push(aaaaSubdomain);
      }
    } catch (error) {
      
    }
  }

  return discoveredSubdomains;
}

router.post('/fetch-domains', async (req, res) => {
  const { domains } = req.body; // Assuming the list of domains is sent in the request body

  try {
    const blacklist = [
      'all.s5h.net',		
      'blacklist.woody.ch',	'bogons.cymru.com',	'cbl.abuseat.org',
      'combined.abuse.ch' ,	'db.wpbl.info'	,'dnsbl-1.uceprotect.net',
      'dnsbl-2.uceprotect.net',	'dnsbl-3.uceprotect.net',	'dnsbl.dronebl.org',
      'dnsbl.sorbs.net'	,'drone.abuse.ch'	,'duinv.aupads.org',
      'dul.dnsbl.sorbs.net',	'http.dnsbl.sorbs.net',
      'ips.backscatterer.org'	,'ix.dnsbl.manitu.net'	,'korea.services.net',
      'misc.dnsbl.sorbs.net',		'orvedb.aupads.org'
       ,	'proxy.bl.gweep.ca'	,'psbl.surriel.com',
      'relays.bl.gweep.ca',	'relays.nether.net',	
      'singular.ttk.pte.hu'	,'smtp.dnsbl.sorbs.net'	,'socks.dnsbl.sorbs.net',
      'spam.abuse.ch'	,'spam.dnsbl.anonmails.de'	,'spam.dnsbl.sorbs.net',
        'spambot.bls.digibase.ca',	'spamrbl.imp.ch',
      'spamsources.fabel.dk'	,'ubl.lashback.com',	'ubl.unsubscore.com',
      'virus.rbl.jp',	'web.dnsbl.sorbs.net',	'wormrbl.imp.ch'
        ,'z.mailspike.net'	,
      'zombie.dnsbl.sorbs.net'		];


const blocklist=['pbl.spamhaus.org','sbl.spamhaus.org','xbl.spamhaus.org'
      ,'zen.spamhaus.org','b.barracudacentral.org','bl.spamcop.net'
      ]

      const selectors = ['google']; 

    const allDomainDetails = await Promise.all(
      domains.map(async (domain) => {
        const [
          mxRecords,
          spfRecords,
          dmarcRecords,
          commonInfo,
          domainInfo,
          nameServers,
          aRecords,
          aaaaRecords,
          discoveredSubdomains,
          blacklistResult,
          blocklistResult,
          // bimiRecord,
            // dkimRecords,
        ] = await Promise.all([
          fetchMxRecords(domain),
          fetchSpfRecords(domain),
          fetchDmarcRecords(domain),
          fetchCommonDomainInfo(domain),
          fetchDomainInfo(domain),
          fetchNameServers(domain),
          fetchARecords(domain),
          fetchAAAARecords(domain),
          discoverSubdomains(domain),
          checkDomainBlacklist(domain,blacklist), 
          checkDomainBlacklist(domain,blocklist), 
          // fetchBimiRecord(domain),
          //  fetchAllDkimRecords(domain, selectors)
        ]);
        console.log("jai hind!!");
        return {
          domain,
          mxRecords,
          spfRecords,
          dmarcRecords,
          registrar: domainInfo.registrar,
          creationDate: domainInfo.creationDate,
          ageInDays: domainInfo.ageInDays,
          nameServers: nameServers,
          httpSupported: commonInfo.httpSupported,
          httpsSupported: commonInfo.httpsSupported,
          tlsRptRecords: commonInfo.tlsRptRecords,
          aRecords,
          aaaaRecords,
          discoveredSubdomains,
          blacklistResult,
          blocklistResult,
          // bimiRecord,
          //  dkimRecords,
        };
      
      })
   
    );

    res.json(allDomainDetails); // Send the array of domain details as the response
  } catch (error) {
    console.error(`An error occurred: ${error.message}`);
    res.status(500).json({ error: 'An error occurred' });
  }
});

router.get('/hello', (req, res) => {
  res.send('Hello, World!');
});


module.exports = router;
