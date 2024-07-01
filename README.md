# XSSHunterX

## Descripción

Esta utilidad está diseñada para probar vulnerabilidades XSS reflejadas en una lista de URLs proporcionadas. Utiliza técnicas de evasión de payloads para detectar posibles vulnerabilidades y ofrece la opción de guardar los resultados en varios formatos (CSV, HTML, TXT).

## Características

- Prueba múltiples URLs para detectar vulnerabilidades XSS reflejadas.
- Utiliza una lista de payloads XSS con técnicas de evasión para evitar la detección.
- Analiza los encabezados HTTP de las respuestas para detectar medidas de seguridad.
- Guarda los resultados en formatos CSV, HTML y TXT.
- Utiliza colores para destacar resultados en la consola, facilitando la identificación de vulnerabilidades.

## Requisitos

- Python 3.x
- Módulos de Python: `requests`, `beautifulsoup4`, `urllib`, `re`, `argparse`, `colorama`, `csv`, `datetime`, `html`

Puedes instalar los módulos requeridos utilizando pip:

```bash
pip install requests beautifulsoup4 colorama
```

## Uso

### Preparación

1. Crea un archivo de texto con las URLs que deseas probar. Por ejemplo, `urls.txt`:
```text
http://example.com/page?param=FUZZ http://test.com/search?query=FUZZ
```

### Ejecución

Ejecuta el script pasando los archivos de URLs y payloads como argumentos, junto con el formato de salida deseado:
```bash
python XSSHunterX.py --urls urls.txt --output csv
```
![[Screenshot_1.png]]

## Resultados

El script generará un archivo de resultados en el formato especificado, incluyendo información sobre las URLs probadas y los payloads que resultaron en vulnerabilidades XSS.

### Formatos de Salida

- **CSV**: `results_YYYYMMDD_HHMMSS.csv`
- **HTML**: `results_YYYYMMDD_HHMMSS.html`
- **TXT**: `results_YYYYMMDD_HHMMSS.txt`
