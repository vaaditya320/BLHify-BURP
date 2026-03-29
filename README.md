# BLHify-BURP

BLHify-BURP is a Java Burp Suite extension that scans proxy responses for social media links and reports potentially broken links as findings inside Burp.

## What it does

- Hooks into Burp proxy traffic.
- Extracts social profile/page URLs from HTTP responses.
- Checks whether links look broken/unavailable on supported platforms.
- Adds issues in Burp when broken social links are found.

## Build and package

### 1) Compile the Java source

Run:

```bash
javac -source 22 -target 22 -cp burp.jar BLHifyBurp.java
```

### 2) Build the final JAR

After compilation, run the Python script to combine class files into the final extension JAR:

```bash
python make.py
```

This creates `BLHify.jar`.

## Load into Burp Suite

1. Open Burp Suite.
2. Go to `Extensions`.
3. Click `Add`.
4. Set extension type to `Java`.
5. Select the `BLHify.jar` file and import it.

If successful, you should see it loaded successfully in Burp.
