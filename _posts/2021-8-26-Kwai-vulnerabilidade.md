---
layout: post
title: Kwai - Roubo de videos privados
categories: [Google,Kwai]
---


## **Overview**
A verificação SSL só é feita se o usuário não estiver logado, um atacante mitm consegue roubar vídeos privados.
versão: 5.5.10.511171

Possivel obter dados dos hosts:

     e eVar4 = (e) g.s("{\"kwaiNetEnabled\":true,\"quicEnabled\":true,\"playerKwaiNetEnabled\":true,\"playerQuicEnabled\":true,\"playerNonquicCdnKwaiNetEnabled\":true,\"quicHints\":{\"urls\":[],\"xnetHosts\":[],\"xnetPlayerHosts\
     ":[\"g-br-cdn.kwai.net:80:443\",\"tx-br-cdn.kwai.net:80:443\",\"g-ind-cdn.kwai.net:80:443\",\"tx-ind-cdn.kwai.net:80:443\",\"ali-ind-cdn.kwai.net:80:443\",\"g-tur-cdn.kwai.net:80:443\",\"tx-ru-cdn.kwai.net:80:443\",\"g-ms-cdn.kwai.net:80:443\",\"ali-ms-cdn.kwai.net:80:443\",\"tx-ms-cdn.kwai.net:80:443\",\"g-id-cdn.kwai.net:80:443\",\"tx-id-cdn.kwai.net:80:443\",\"ali-id-cdn.kwai.net:80:443\",\"ws-id-cdn.kwai.net:80:443\",\"tx-vn-cdn.kwai.net:80:443\",\"ws-vn-cdn.kwai.net:80:443\"],\"idleConnTimeoutSeconds\":180,\"preConnectNonAltsvc\":true,\"altsvcBrokenTimeBase\":300,\"altsvcBrokenTimeMax\":86400}}", e.class);
     

## O roubo de videos privados acontece quando o usuario aciona a seguinte atividade:

    com.yxcorp.download.*

# Prova de conceito

Usando (mitmproxy) na mesma rede que a vitima é possível obter vídeos privados.

**Video Poc:**
[Video no drive](https://drive.google.com/file/d/1tfw66gAmuKCA9MzKxSRFFkc0X8b6nuZ2/view?usp=sharing)

|REPORTADO AO GOOGLE| 08.07.2021|
|--|--|
|  ACEITADO| 10.07.2021 |
|--|--|
|FIXO| 27.07.2021 |
|--|--|

