# AskJOE

## What is AskJOE?
This is a Ghidra plugin that calls [OPENAI](https://openai.com/) to give meaning to decompiled functions. It was based on the [Gepetto](https://github.com/JusticeRage/Gepetto) idea.

This one is much more simple and instead work in IDA Pro we can use it to get some insights in Ghidra! :)

![AskJOE Running](/imgs/AskJOE-running.png "AskJOE Running")

## Dependencies
- Requests: `pip install requests`
- [Python3](https://www.python.org/downloads/)
- [Ghidrathon](https://github.com/mandiant/Ghidrathon)

## How to install?
- An easy way is open the Ghidra Script Manager > Create a New Script > Paste AskJOE > Done! :)
