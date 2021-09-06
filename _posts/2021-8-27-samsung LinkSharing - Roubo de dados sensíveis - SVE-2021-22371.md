---
layout: post
title: Samsung LinkSharing - Roubo de dados sensíveis - SVE-2021-22371
categories: [Android,Samsung]
---

## **Visão Geral**


A configuração inadequada (SSL) permite que um invasor roube dados sensíveis transmitidos no host do aplicativo.
Versão: 12.3.00.5

    private final Cursor createResultCursor(List<DownloadedContent> list) {
        MatrixCursor matrixCursor = new MatrixCursor(new String[]{"_id", "file_name", "file_path", "mime_type", "file_size", "source"});
        for (T t : list) {
            matrixCursor.addRow(new Object[]{Long.valueOf(t.getId()), t.getFileName(), t.getFilePath(), t.getMimeType(), Long.valueOf(t.getFileSize()), "https://linksharing.samsungcloud.com"});
        }
        return matrixCursor;
    }

## O roubo de dados sensíveis acontece quando a outra ponta recebe o link para fazer o download dos arquivos.
`~ http://linksharing.samsungcloud.com/TESTCODE123`

![](https://rafaellim4.github.io/images/diagsam.jpeg)

|REPORTADO A SAMSUNG| 27.06.2021 |
|--|--|
| ACEITADO| 08.07.2021 |
| FIXO | 29.07.2021 |
