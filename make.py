# make_jar.py
import zipfile

manifest = "Manifest-Version: 1.0\nMain-Class: BLHifyBurp\n\n"

with zipfile.ZipFile('BLHify.jar', 'w') as jar:
    jar.writestr('META-INF/MANIFEST.MF', manifest)
    jar.write('BLHifyBurp.class')
    jar.write('BLHifyBurp$BLHIssue.class')

print('BLHify.jar created!')
