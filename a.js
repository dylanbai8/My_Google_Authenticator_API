// 获取get值
function getQueryVariable(variable)
{
       var query = decodeURI(window.location.search.substring(1));
       var vars = query.split("&");
       for (var i=0;i<vars.length;i++) {
               var pair = vars[i].split("=");
               if(pair[0] == variable){return pair[1];}
       }
       return(false);
}

// 给定密钥“K”和时间戳“t”(从纪元开始以30s为单位)，返回TOTP码。
function totp(K,t) {
  function sha1(C){
    function L(x,b){return x<<b|x>>>32-b;}
    var l=C.length,D=C.concat([1<<31]),V=0x67452301,W=0x88888888,
        Y=271733878,X=Y^W,Z=0xC3D2E1F0;W^=V;
    do D.push(0);while(D.length+1&15);D.push(32*l);
    while (D.length){
      var E=D.splice(0,16),a=V,b=W,c=X,d=Y,e=Z,f,k,i=12;
      function I(x){var t=L(a,5)+f+e+k+E[x];e=d;d=c;c=L(b,30);b=a;a=t;}
      for(;++i<77;)E.push(L(E[i]^E[i-5]^E[i-11]^E[i-13],1));
      k=0x5A827999;for(i=0;i<20;I(i++))f=b&c|~b&d;
      k=0x6ED9EBA1;for(;i<40;I(i++))f=b^c^d;
      k=0x8F1BBCDC;for(;i<60;I(i++))f=b&c|b&d|c&d;
      k=0xCA62C1D6;for(;i<80;I(i++))f=b^c^d;
      V+=a;W+=b;X+=c;Y+=d;Z+=e;}
    return[V,W,X,Y,Z];
  }
  var k=[],l=[],i=0,j=0,c=0;
  for (;i<K.length;){
    c=c*32+'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.
      indexOf(K.charAt(i++).toUpperCase());
    if((j+=5)>31)k.push(Math.floor(c/(1<<(j-=32)))),c&=31;}
  j&&k.push(c<<(32-j));
  for(i=0;i<16;++i)l.push(0x6A6A6A6A^(k[i]=k[i]^0x5C5C5C5C));
  var s=sha1(k.concat(sha1(l.concat([0,t])))),o=s[4]&0xF;
  return ((s[o>>2]<<8*(o&3)|(o&3?s[(o>>2)+1]>>>8*(4-o&3):0))&-1>>>1)%1000000;
}

// 定期检查我们是否需要更新UI。如果只调用这个函数作为重大状态变化的直接结果，效率会高一点。但是轮询很便宜，并且让代码变得更容易。
var lastsecret,lastlabel,lastepochseconds,lastoverrideepoch;
var lasttimestamp,lastoverride,lastsearch;
function refresh() {
  // 计算当前TOTP代码
  var k=getQueryVariable("secret").
    replace(/[^ABCDEFGHIJKLMNOPQRSTUVWXYZ234567]/gi, '');
  var d=document.getElementById('overrideepoch').value.replace(/[^0-9]/g, '');
  if (d) e=parseInt(d); else e=Math.floor(new Date().getTime()/1000);
  var t=Math.floor(e/30);
  var s=document.getElementById('override').value.replace(/[^0-9]/g, '');
  if (s) { t=parseInt(s); e=30*t; }
  var label=getQueryVariable("label");
  var search=getQueryVariable("search");

  // 如果TOTP代码已更改(由于用户编辑或经过的时间)，请更新用户界面。
  if (k != lastsecret || label != lastlabel || e != lastepochseconds ||
      d != lastoverrideepoch || t != lasttimestamp || s != lastoverride ||
      search != lastsearch) {
    if (d != lastoverrideepoch) {
      document.getElementById('override').value = '';
      s = '';
    } else if (s != lastoverride) {
      document.getElementById('overrideepoch').value = '';
      d = '';
    }
    lastsecret=k;
    lastlabel=label;
    lastepochseconds=e;
    lastoverrideepoch=d;
    lasttimestamp=t;
    lastoverride=s;
    lastsearch=search;

    var code=totp(k,t);


    // 显示自1970年1月1日午夜以来的当前时间，以秒为单位，以30s为增量。或者，让用户覆盖这个时间戳。
    document.getElementById('epoch').innerHTML=e;
    document.getElementById('ts').innerHTML=t;

    // 如果用户手动输入TOTP代码，请尝试在25小时内找到匹配的代码。
    var result='';
    if (search && !!(search=parseInt(search))) {
      for (var i=0; i < 25*120; ++i) {
        if (search == totp(k, t+(i&1?-Math.floor(i/2):Math.floor(i/2)))) {
          if (i<2) {
            result='验证码正确！';
            break;
          }
          if (i >= 120) {
            result=result + Math.floor(i/120) + '小时 ';
            i%=120;
          }
          if (i >= 4) {
            result=result + Math.floor(i/4) + '分钟 ';
            i%=4;
          }
          if (i&2) {
            result=result + '30秒 ';
          }
          if (i&1) {
            result='验证码已在 ' + result + '前过期！';
          } else {
            result='验证码将在 ' + result + '后有效！';
          }
          break;
        }
      }
      if (!result) {
        result='在±12小时内不会出现此验证码！';
      }
    }


	// 显示标签
	if(label != false){
    document.getElementById('inlabel').innerHTML='备注标签：' + label;
	}

    // 显示当前的TOTP代码。当code是5位数时首位补0
	var len = code.toString().length;
	if(len < 6){code = '0' + code;}
	if(label != false || search != false){
    document.getElementById('totp').innerHTML='当前验证码：' + code;

    // 如果可能，将Javascript报告的当前时间与AppEngine报告的“官方”时间进行比较。如果有任何显著差异，显示警告信息。由于往返延迟，我们总是期望至少有一个小的时间偏差，而我们并没有费心去补偿。
    if (typeof timeskew != undefined) {
      var ts=document.getElementById('timeskew');
      if (Math.abs(timeskew) < 2000) {
        ts.style.color='';
        ts.innerHTML='时间校对：您的计算机时间设置正确。TOTP 验证码将被精确计算。';
      } else if (Math.abs(timeskew) < 30000) {
        ts.style.color='';
        ts.innerHTML='时间校对：您的计算机时间慢 ±' +
          (Math.round(Math.abs(timeskew)/1000)) + ' 秒。' +
          '这在可接受的公差范围内，但计算的 TOTP 验证码可能与移动应用程序中的不同。';
      } else {
        ts.style.color='#dd0000';
        ts.innerHTML='<b>时间校对：您的计算机时间慢 ±' +
          (Math.round(Math.abs(timeskew)/1000)) + ' 秒。' +
          '计算的 TOTP 验证码可能是错误的！</b>';
      }
    }

    // 计算OTPAuth URL和相关的二维码
    var h='https://api.qrserver.com/v1/create-qr-code/?size=155x155'+
      '&data=otpauth://totp/'+encodeURI(label)+'%3Fsecret%3D'+k;
    var a=document.getElementById('authurl')
    a.innerHTML='otpauth://totp/'+label+'?secret='+k;
    a.href=h;
    document.getElementById('aqr').href=h;
    var q=document.getElementById('qr');
    q.src=h;
    q.alt=label+' '+k;
    q.title=label+' '+k;

	}else{
    document.getElementById('totp').innerHTML=code;
	}

	// 对比传入code并验证
	if(search != false){
    document.getElementById('intotp').innerHTML='传入验证码：' + search;
    document.getElementById('searchresult').innerHTML='验证结果：' + result;
	}

  }
}

// https://github.com/google/google-authenticator-libpam