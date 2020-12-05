let raw;
let requestOptions;
let resultado;
let userURL;
let urlValida = /https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,4}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)?/gi;
let divResultado = document.getElementById("divResultado");
let loader = document.getElementById('loader');

function htmlResultado(urlConsultada, ameacas, descricoes) {
return `
<header class="scan-result__header row">
<div class="column">
    <img src="images/alert-icon.png" alt="Danger icon"/>
</div>

<div class="column">
    <h2 class="scan-result__header__title">Acesso Bloqueado</h2>
    <p class="scan-result__header__description">O site analisado apresenta ameaça de segurança.</p>
</div>
</header>

<div class="scan-result__body">
<div class="row">
    <div class="column">Endereço:</div>
    <div class="column">${urlConsultada}</div>
</div>

<div class="row">
    <div class="column">Tipo de ameaça:</div>
    <div class="column">${ameacas.join(", ")}</div>
</div>

<div class="row">
    <div class="column">Impacto:</div>
    <div class="column">${descricoes.join("\n")}</div>
</div>
</div>
`
}

function htmlMensagem(mensagem, icone){ 
return `
<div class="scan-result__header row">
<div class="column">
    <img src="${icone !== 'sucesso' ? 'images/alert-icon.png' : 'images/success-icon.png'}"/>
</div>

<div class="column">
    <p class="scan-result__header__description" style="font-size: 28px">${mensagem}</p>
</div>
</div>
`
}
function consultaURL(){
  divResultado.classList.add('hidden');
  configuraRequest();
  if(userURL.match(urlValida)){
    loader.classList.remove('hidden');
    fetchRequest();
  } else {
    loader.classList.add('hidden');
    divResultado.classList.remove('hidden');
    divResultado.innerHTML = htmlMensagem('Utilize uma URL válida!')
  }
}

function configuraRequest(){
  let myHeaders = new Headers();
  myHeaders.append("Content-Type", "application/json");
  myHeaders.append("Cache-Control", "no-cache");
  userURL = document.getElementById("userInput").value;
  raw = JSON.stringify(
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
        {"url": userURL}
      ]
    }}
  );
  requestOptions = {
    method: 'POST',
    headers: myHeaders,
    body: raw,
    redirect: 'follow'
  };
}
async function fetchRequest(){
  await fetch("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=AIzaSyAEjr3GwnHChHtyyegW2azCgw3Cazt2rE4", requestOptions)
  .then(response => response.text())
  .then(result => escreveResposta(JSON.parse(result)))
  .catch(error => escreveErro(error));
}

function escreveResposta(resultado){
  const urlConsultada = userURL;
  loader.classList.add('hidden');
  if (resultado.matches){
    const dicioAmeacas = {
      "THREAT_TYPE_UNSPECIFIED": 'Ameaça desconhecida',
      "MALWARE": 'Malware',
      "SOCIAL_ENGINEERING": 'Engenharia social (phishing)',
      "UNWANTED_SOFTWARE": 'Software indesejado',
      "POTENTIALLY_HARMFUL_APPLICATION": 'Aplicação potencialmente danosa'
    }
    const dicioDescricoes = {
      "THREAT_TYPE_UNSPECIFIED": 'Encontramos ameaças que ainda não se encaixam em nenhum das categorias',
      "MALWARE": 'Encontramos indícios de softwares mal intencionados potencialmente danosos, com risco de invasões e roubo de informações',
      "SOCIAL_ENGINEERING": 'Encontramos tentativas fraudulentas de roubar informações de forma disfarçada',
      "UNWANTED_SOFTWARE": 'Encontramos downloads automáticos de softwares indesejáveis e potencialmente destrutivos',
      "POTENTIALLY_HARMFUL_APPLICATION": 'Encontramos resquícios de aplicações já conhecidas por danos usuários, informações ou dispositivos'
    }
    
    let ameacas=[];
    let descricoes=[]
    resultado.matches.forEach(element => {
      ameacas.push(dicioAmeacas[element.threatType]);
      descricoes.push(dicioDescricoes[element.threatType])
    });
    console.log(urlConsultada);
    console.log(ameacas.join(", "));
    console.log(descricoes.join("\n"));
    divResultado.classList.remove('hidden');
    divResultado.innerHTML = htmlResultado(urlConsultada, ameacas, descricoes)
  }
  else{
    divResultado.classList.remove('hidden');
    divResultado.innerHTML = htmlMensagem('O Site é seguro!', 'sucesso');
    window.open(urlConsultada,'_blank');
  }
}

function escreveErro(erro){
  loader.classList.add('hidden');
  divResultado.classList.remove('hidden');
  divResultado.innerHTML = htmlMensagem(erro);
}

// {"url":"https://testsafebrowsing.appspot.com/s/phishing.html"},
// {"url":"http://malware.testing.google.test/testing/malware/"},
// {"url":"https://testsafebrowsing.appspot.com/s/unwanted.html"}