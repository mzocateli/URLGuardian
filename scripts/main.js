let myHeaders = new Headers();
myHeaders.append("Content-Type", "application/json");
myHeaders.append("Cache-Control", "no-cache");

let raw = JSON.stringify(
  {
    "client": {
      "clientId":"fatecopias",
      "clientVersion":"1.0.0"
  },
  "threatInfo": {
    "threatTypes":["THREAT_TYPE_UNSPECIFIED","MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
    "platformTypes":["ANY_PLATFORM"],
    "threatEntryTypes":["URL"],
    "threatEntries":[
      {"url":"https://testsafebrowsing.appspot.com/s/phishing.html"},
      {"url":"http://malware.testing.google.test/testing/malware/"},
      {"url":"https://testsafebrowsing.appspot.com/s/unwanted.html"}
    ]
  }}
);

const requestOptions = {
  method: 'POST',
  headers: myHeaders,
  body: raw,
  redirect: 'follow'
};

fetch("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=AIzaSyAEjr3GwnHChHtyyegW2azCgw3Cazt2rE4", requestOptions)
  .then(response => response.text())
  .then(result => console.log(result))
  .catch(error => console.log('error', error));

//TODO: Separar código em funções
//TODO: Setar URL como variável
//TODO: Capturar URL quando pesquisar
//TODO: Disparar fetch quando pesquisar
//TODO: Capturar resposta em objeto
//TODO: Tratar resposta legível para o usuário (tipo de mensagem legíveis)
//TODO: Exibir resposta em span ou table com cores