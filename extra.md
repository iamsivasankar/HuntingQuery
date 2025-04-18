# Extra

```kusto
// Some code

KQL 


let words = datatable(index: int, encoded: string)
[
    1, "SnVzdA==",      // "Just" in Base64
    2, "YW5vdGhlcg==",  // "another" in Base64
    3, "S3VzdG8=",      // "Kusto" in Base64
    4, "aGFja2Vy"       // "hacker" in Base64
];
words
| extend decoded = base64_decode_tostring(encoded) // Decode Base64
| extend styled = strcat(index, "️⃣ ", decoded) // Stylize with index emojis
| summarize finalResult = strcat_array(make_list(styled), " | ") // Combine all styled results
| extend finalOutput = strcat("🌟 ", finalResult, " 🌟") // Add flair
| project finalOutput

```
