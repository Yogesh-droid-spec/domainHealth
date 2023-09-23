const puppeteer = require('puppeteer')
const fs = require('fs')
async function getPageContent(){
    const browser = await puppeteer.launch({
        headless:'new',
        args:[
            '--no-sandbox'
        ]
    });

    const page = (await browser.pages())[0];
    await page.goto("https://kombai.com/");
    const extractedText = await page.$eval('*',(el)=>el.innerText);
    const extractedHTML = await page.content();
    console.log(extractedText);
    fs.appendFile('puppeteer.html', extractedHTML, err => {
        if (err) {
          console.error(err);
        }
      });
    await browser.close()
}

getPageContent();













v=BIMI1