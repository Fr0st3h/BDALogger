import os
import re
from bs4 import BeautifulSoup
from loguru import logger


class EnforcementUpdater:
    def __init__(self, inputDir, outputDir):
        self.inputDir = inputDir
        self.outputDir = outputDir
        self.lol = self.getLolValue()

    def getLolValue(self):
        with open(f'{self.inputDir}/enforcement.html', 'r', encoding='utf-8') as f:
            html = f.read()
        soup = BeautifulSoup(html, 'html.parser')
        return soup.find('meta', {'http-equiv': 'Content-Security-Policy'}).get('content').split('data: ')[1].split(' ')[0]

    def updateApiJs(self):
        with open(f'{self.inputDir}/api.js', 'r', encoding='utf-8') as file:
            fileContent = file.read()

        regexPattern = r'\d+\.\d+\.\d+/enforcement\.[a-fA-F0-9]+\.html'
        updatedContent = re.sub(regexPattern, 'enforcement.html', fileContent)
        
        #regexPattern = r'(return function\s*\(\s*([^)]*)\s*\)\s*\{\s*return\s+t\.apply\(this,\s*arguments\)\s*\})'
        #updatedContent = re.sub(regexPattern, self.addConsoleLogs, updatedContent)

        injection = f'''var xhr = new XMLHttpRequest();
                xhr.open("POST", "http://127.0.0.1:1337/fingerprint", false);
                xhr.setRequestHeader("Content-Type", "application/json");
                xhr.send(JSON.stringify({{"bda": JSON.stringify(r),decryptionKey: 'None',useragent: navigator.userAgent,version: "{enforcementVersion}",}}));
            '''

        regexPattern = r'(case\s+14:\s*)(?=if\s*\(\s*o\s*=\s*t\.sent,)'
        updatedContent = re.sub(regexPattern, r'\1' + injection, fileContent)

        self.writeFile(f'{self.outputDir}/{self.lol}/v2/11111111-1111-1111-1111-111111111111/api.js', updatedContent)
        logger.success("api.js updated.")

    def extractEnforcementDetails(self):
        with open(f'{self.inputDir}/api.js', 'r', encoding='utf-8') as file:
            fileContent = file.read()

        regexPattern = r'\d+\.\d+\.\d+/enforcement\.[a-fA-F0-9]+\.html'
        matches = re.findall(regexPattern, fileContent)

        if matches:
            enforcementVersion = matches[0].split("/")[0]
            enforcementHash = matches[0].split("/")[1].split(".")[1]
            logger.info(f'Found Enforcement Version {enforcementVersion} ({matches[0]})')
            return enforcementVersion, enforcementHash
        else:
            raise ValueError("No matches found for enforcement version and hash.")

    def updateHtmlFiles(self, enforcementHash):
        inputFilePath = f'{self.inputDir}/enforcement.html'
        outputFilePath = f'{self.outputDir}/{self.lol}/v2/enforcement.html'

        with open(inputFilePath, 'r', encoding='utf-8') as file:
            fileContent = file.read()

        updatedContent = self.removeAttributes(fileContent)
        updatedContent = updatedContent.replace(f'enforcement.{enforcementHash}.js', 'enforcement.js')

        self.writeFile(outputFilePath, updatedContent)
        logger.success("enforcement.html updated.")

    def removeAttributes(self, content):
        regexPattern = r'\s*(crossorigin="anonymous"|integrity="sha384-[^"]+"|data-nonce="[^"]+")'
        return re.sub(regexPattern, '', content)

    def writeFile(self, filePath, content):
        os.makedirs(os.path.dirname(filePath), exist_ok=True)
        with open(filePath, 'w', encoding='utf-8') as file:
            if('.js' in filePath):
                file.write(r"if (!String.prototype.searchOld) String.prototype.searchOld = String.prototype.search;String.prototype.search = function (...args) { if (args[0] == '(((.+)+)+)+$' && this.includes('\n')) return 0; console.log(this); return this.searchOld(...args) }"+"\n")
            file.write(content)

    def updateEnforcementJs(self):
        with open(f'{self.inputDir}/enforcement.js', 'r', encoding='utf-8') as file:
            fileContent = file.read()

        outputFilePath = f'{self.outputDir}/{self.lol}/v2/enforcement.js'
        self.writeFile(outputFilePath, fileContent)
        logger.success("enforcement.js updated.")

    def addConsoleLogs(self, match):
        fullMatch = match.group(1)
        args = match.group(2).split(',')

        if len(args) > 5:
            logStatements = "\n".join([self.createLogStatement(arg.strip()) for arg in args])
            newFunctionBody = f"""return function ({', '.join(args)}) {{
                {logStatements}
                return t.apply(this, arguments);
            }}"""
            return newFunctionBody
        return fullMatch

    def createLogStatement(self, arg):
        return f'if({arg}.toString().includes("bda")) {{console.log("Found BDA! Sending To Server.."); ' \
            f'var currentTime = Math.floor(Date.now() / 1000); var timeInHours = currentTime - (currentTime % 21600);' \
            f'var xhr = new XMLHttpRequest();xhr.open("POST", "http://127.0.0.1:1339/fingerprint", false);' \
            f'xhr.setRequestHeader("Content-Type", "application/json");xhr.send(JSON.stringify({{"bda": ' \
            f'decodeURIComponent({arg}.toString().split("bda=")[1].split(",")[0]),decryptionKey: `${{navigator.userAgent}}' \
            f'${{timeInHours}}`,useragent: navigator.userAgent,version: "{enforcementVersion}",}})); return;}}'
    
    

    def generateMainHtml(self):
        
        mainHtmlContent = f"""
<html>
<head>
    <meta charset="utf-8">
    <script>
        var script = document.createElement('script');
        script.type = 'text/javascript';
        script.async = true;
        script.defer = true;
        script.src = '{self.lol}/v2/' + '11111111-1111-1111-1111-111111111111' + '/api.js';
        script.setAttribute('data-callback', 'setupEnforcement');

        document.getElementsByTagName('head')[0].appendChild(script);

        function setupEnforcement(myEnforcement) {{
            myEnforcement.setConfig({{
                selector: '#logger',
                language: navigator.language,
                mode: 'inline',
            }});
        }}
    </script>
</head>
<body style="margin: 0px">
    <div id="logger"></div>
</body>
</html>
"""
        self.writeFile(f'{self.outputDir}/index.html', mainHtmlContent)
        logger.success("index.html generated.")


if __name__ == "__main__":
    logger.info('Starting BDA Logger Injector..')
    inputDir = 'input'
    outputDir = 'output'
    try:
        
        requiredFIles = ['api.js', 'enforcement.html', 'enforcement.js']

        for file in requiredFIles:
            if os.stat(f'{inputDir}/{file}').st_size == 0:
                print(f'File {file} is empty, please ensure you have put the code in the file.')
                os._exit(0)
                
        updater = EnforcementUpdater(inputDir, outputDir)
        enforcementVersion, enforcementHash = updater.extractEnforcementDetails()
        updater.updateApiJs()
        updater.updateHtmlFiles(enforcementHash)
        updater.updateEnforcementJs()
        updater.generateMainHtml()

        logger.info('Finished Updating Files..')
    except Exception as e:
        print(f"Error: {e}")
