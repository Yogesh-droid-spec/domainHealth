const express = require('express');
const router = express.Router();
const dns = require('dns');
const whois = require('whois-json');
const http = require('http');
const https = require('https');
const lookup = require('dnsbl-lookup');
const fs = require('fs');
const stream = require('stream');
const { log } = require('console');
const axios = require('axios');



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
async function fetchBimiRecord(domain, timeoutMs = 3000) {
  return new Promise(async (resolve) => {
    const timer = setTimeout(() => {
      console.log('DNS query timed out for', domain);
      resolve([]);
    }, timeoutMs);

    try {
      const bimiRecords = await dns.promises.resolveTxt(`default._bimi.${domain}`);
      clearTimeout(timer);

      
      

      if (bimiRecords) {
        resolve(bimiRecords);
      } else {
        console.error(`BIMI Record not found for ${domain}`);
        resolve([]);
      }
    } catch (error) {
      clearTimeout(timer);
      if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
        console.error(`BIMI Record not found for ${domain}`);
        resolve([]);
      } else if (error.code === 'ESERVFAIL') {
        console.error(`DNS resolution error for ${domain}: Server failure`);
        resolve([]);
      } else {
        console.error('Error fetching BIMI Record for', domain, error.message);
        resolve([]);
      }
    }
  });
}


async function checkDomainBlacklist(domain, blocklistArray) {
  return new Promise((resolve, reject) => {
    const uribl = new lookup.uribl([domain], blocklistArray);
    const result = {};
    console.log("domain blacklist!! check");
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
     return [];
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
      return []; 
    } else if (error.code === 'ESERVFAIL') {
      console.error(`DNS resolution error : Server failure`);
      return []; 
    } else {
     return [];
      throw error; 
    }
  }
}

// Function to fetch MX records for a domain
async function fetchMxRecords(domain) {
  try {
    const mxRecords = await dns.promises.resolveMx(domain);
    console.log("MX fetching success!!");
    return mxRecords;
  } catch (error) {
    if (error.code === 'ENODATA'||error.code==='ENOTFOUND') {
      console.log("MX fetching error!!");
      return []; // Return an empty array if MX records are not found (ENOTFOUND)
    } else {
     return[];
      throw error; // Throw other DNS resolution errors
    }
  }
}

// Function to fetch SPF records for a domain
async function fetchSpfRecords(domain) {
  try {
    const txtRecords = await dns.promises.resolveTxt(domain);
    const spfRecords = txtRecords.filter(record => record[0].startsWith('v=spf1'));
    console.log("SPF Fetching!!");
    return spfRecords;
  } catch (error) {
    if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
      return []; 
    } else if (error.code === 'ESERVFAIL') {
      console.error(`DNS resolution error : Server failure`);
      return []; 
    } else {
     return[];
      throw error;
    }
  }
}

// Function to fetch DMARC records for a domain
async function fetchDmarcRecords(domain) {
  try {
    const dmarcSubdomain = '_dmarc.' + domain;
    const txtRecords = await dns.promises.resolveTxt(dmarcSubdomain);
    console.log("DMARC fetching!!");
    return txtRecords;
  } catch (error) {
    if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
      return []; // Return an empty array if DMARC records are not found (ENOTFOUND)
    } else if (error.code === 'ESERVFAIL') {
      console.error(`DNS resolution error for : Server failure`);
      return []; // Handle ESERVFAIL error gracefully
    } else {
       return [];
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
     console.log("dinfo fetches");
    return {
      httpSupported,
      httpsSupported,
      tlsRptRecords
    };
  } catch (error) {
    console.log("dinfo fetches error");
    throw error;
  }
}

// Function to check if HTTP is supported
async function checkHttpSupport(domain) {
  try {
    const response = await axios.head(`http://${domain}`, { timeout: 1500 });

    if (response.status == 200) {
      return true; // HTTP is supported
    } else if (response.status === 405) {
      console.warn(`HTTP request error for ${domain}: Method Not Allowed (Status Code 405)`);
      return false;
    } else {
      console.error(`HTTP request error for ${domain}: Unexpected Status Code ${response.status}`);
      return false;
    }
  } catch (error) {
    console.error(`HTTP request error for ${domain}: ${error.message}`);
    return false;
  }
}

// Function to check if HTTPS is supported
async function checkHttpsSupport(domain) {
  try {
    const response = await axios.head(`https://${domain}`, { timeout: 1500 });

    if (response.status >= 200) {
      return true; // HTTPS is supported
    } else if (response.status === 405) {
      console.warn(`HTTPS request error for ${domain}: Method Not Allowed (Status Code 405)`);
      return false;
    } else {
      console.error(`HTTPS request error for ${domain}: Unexpected Status Code ${response.status}`);
      return false;
    }
  } catch (error) {
    console.error(`HTTPS request error for ${domain}: ${error.message}`);
    return false;
  }
}

async function checkDomainForwarding(domain) {
  try {
    const response = await axios.get(`http://${domain}`, {
      maxRedirects: 0,
      validateStatus: (status) => status === 301 || status === 302,timeout:1000
    });

    if (response.headers['location']) {
      return {
        isForwarding: true,
        forwardingTo: response.headers['location'],
      };
    } else {
      return {
        isForwarding: false,
      };
    }
  } catch (error) {
    console.error(`Error checking domain forwarding for ${domain}: ${error.message}`);
    
    if (error.response) {
      // If there's a response in the error, check the status code
      if (error.response.status === 405) {
        // Handle 405 (Method Not Allowed) error
        return {
          isForwarding: false,
        };
      } else {
        // Handle other HTTP error status codes
        return {
          isForwarding: false,
          error: `HTTP error: ${error.response.status}`,
        };
      }
    } else {
      // Handle network errors or timeouts
      return {
        isForwarding: false,
        error: `Network error: ${error.message}`,
      };
    }
  }
}





// Function to fetch TLS-RPT (TLS Reporting Policy and Trust) records for a domain
async function fetchTlsRptRecord(domain) {
  try {
    const tlsRptSubdomain = '_tlsrpt.' + domain;
    const records = await dns.promises.resolveTxt(tlsRptSubdomain);
    console.log("TLs success!!");
    return records;
  } catch (error) {
    if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
      return []; // Return an empty array if DMARC records are not found (ENOTFOUND)
    } else if (error.code === 'ESERVFAIL') {
      console.error(`DNS resolution error : Server failure`);
      return []; // Handle ESERVFAIL error gracefully
    } else {
     return [];
      throw error; // Throw other DNS resolution errors
    }
  }
}

async function fetchDomainInfoWithTimeout(domain, timeoutMs = 3000) {
  try {
    return await Promise.race([
      fetchDomainInfo(domain),
      new Promise((_, reject) => {
        setTimeout(() => {
          reject(new Error('Domain info fetch timed out'));
        }, timeoutMs);
      }),
    ]);
  } catch (error) {
    console.error(`Error fetching domain info for ${domain}: ${error.message}`);
    if (error.message === 'Domain info fetch timed out') {
      return {
        registrar: '',
        creationDate: '',
        ageInDays: '',
        error: `Domain info fetch for ${domain} timed out. Please try again later.`,
      };
    } else if (error.code === 'ECONNRESET') {
      return {
        registrar: '',
        creationDate: '',
        ageInDays: '',
        error: `Connection reset while fetching domain info for ${domain}. Please try again later.`,
      };
    } else {
      return {
        registrar: '',
        creationDate: '',
        ageInDays: '',
        error: `Error fetching domain info: ${error.message}`,
      };
    }
  }
}

async function fetchDomainInfo(domain) {
  try {
    const whoisData = await whois(domain);

    const creationDate = whoisData.creationDate;
    const registrar = whoisData.registrar;

    if (!creationDate || !registrar) {
      return {
        registrar: '',
        creationDate: '',
        ageInDays: '',
      };
    }

    // Calculate domain age
    const currentDate = new Date();
    const ageInMilliseconds = currentDate - new Date(creationDate);
    const ageInDays = Math.floor(ageInMilliseconds / (1000 * 60 * 60 * 24));

    return {
      registrar: registrar,
      creationDate: creationDate,
      ageInDays: ageInDays,
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
    console.log("ns fetching success");
    return nameServers;
  } catch (error) {
    if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
      return []; // Return an empty array if DMARC records are not found (ENOTFOUND)
    } else if (error.code === 'ESERVFAIL') {
      console.error(`DNS resolution error : Server failure`);
      return []; // Handle ESERVFAIL error gracefully
    } else {
     return[];
      throw error; // Throw other DNS resolution errors
    }
  }
}


// Function to fetch A (IPv4) records for a domain
async function fetchARecords(domain) {
  try {
    const addresses = await dns.promises.resolve4(domain);
    console.log('A record fetch success');
    return addresses;
  } catch (error) {
    console.log('A record fetch error');
    return [];
  }
}

// Function to fetch AAAA (IPv6) records for a domain
async function fetchAAAARecords(domain) {
  try {
    const addresses = await dns.promises.resolve6(domain);
    console.log('AAA record fetch success');
    return addresses;
  } catch (error) {
    console.log('AAA record fetch error');
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
 console.log("subdomain check!!");
  return discoveredSubdomains;
}

router.post('/fetch-domains', async (req, res) => {
  const { domains } = req.body; 

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
          bimiRecord,
            dkimRecords,
            isDomainForwarded,
        ] = await Promise.all([
          fetchMxRecords(domain),
          fetchSpfRecords(domain),
          fetchDmarcRecords(domain),
          fetchCommonDomainInfo(domain),
          fetchDomainInfoWithTimeout(domain),
          fetchNameServers(domain),
          fetchARecords(domain),
          fetchAAAARecords(domain),
          discoverSubdomains(domain),
          checkDomainBlacklist(domain,blacklist), 
          checkDomainBlacklist(domain,blocklist), 
          fetchBimiRecord(domain),
           fetchAllDkimRecords(domain, selectors),
           checkDomainForwarding(domain)
        ]);
   
    const isForwarded = isDomainForwarded !== null && isDomainForwarded !== undefined;


    const forwardedDomain = isForwarded ? isDomainForwarded : '';
        console.log("Domain Processed😎😁😊😊😎");
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
          bimiRecord,
           dkimRecords,
           forwardedDomain,
        };
      
      })
   
    );

    res.json(allDomainDetails); // Send the array of domain details as the response
  }  catch (error) {
    console.error(`Error processing domain: ${error.message}`);
    return {
      error: `Error processing domain: ${error.message}`,
    };
  }
});

router.get('/hello', (req, res) => {
  res.send('Hello, World!');
});


module.exports = router;
