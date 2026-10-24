# AVAGELM: my little LLM safety lab

Hey, I’m Akshita, a B.Tech CSE student. I got curious about a slightly scary question: **if an AI reads an email or webpage with sneaky instructions in it, could that text talk the AI into using a tool?**

So I built AVAGELM to poke at that idea. The rule I’m testing is simple: **the model can suggest an action, but my Python code gets the final say.** This is a small local project, not a claim that I’ve solved AI security.

## What happens in my demo

1. Python makes 250 sample messages in five groups, such as hidden instructions in search results or a document pretending to have permission.
2. A local Llama 3.2 model reads a few examples and may ask to use a tool.
3. The same request goes through two routes. The baseline runs a valid request without checking its source. The protected route checks the tool, the source label, and the arguments first.
4. The Streamlit page lets me look at the attacks, model requests, decisions, results, and logs.

The audit’s `export_demo_records` tool is fake and returns made-up sample data. It does not export real records or touch a database. I also made a tiny task-list example to show how another Python app could send its tools through the same kind of check.

## Try it on your computer

You’ll need Python 3.10 or newer, Streamlit, and Ollama. I used Llama 3.2 through Ollama on my laptop.

In PowerShell, open this project folder and install the project:

```powershell
python -m pip install -e ".[ui,signing]"
ollama pull llama3.2:latest
```

Keep Ollama running in one terminal:

```powershell
ollama serve
```

Then, in another terminal, start my page:

```powershell
streamlit run streamlit_app.py
```

Open the local address Streamlit prints, usually `http://localhost:8501`. In VS Code, open this folder and choose **AVAGELM: Streamlit** from **Run and Debug**. The task demo saves its little task list under `artifacts/task_demo/` on your computer.

If you only want the terminal version, these commands are still here:

```powershell
python main.py --check --provider ollama --model llama3.2:latest
python main.py --orchestrate --trials 5 --provider ollama --model llama3.2:latest --output artifacts
python main.py --verify-audit --output artifacts
```

## What I saw in a local run

I ran the five attack groups five times each: 25 model calls, with no provider errors. The model requested the fake tool 20 times. The deliberately unsafe baseline ran those 20 requests; the protected route blocked all 20. I also ran 1,250 separate checks of the Python rule, and all were blocked because their source label was untrusted.

Those numbers describe **one small run on my setup**. The 1,250 checks are rule checks, not 1,250 extra model attacks. I repeated fixed examples, used one local model, and used a fake tool, so this is not proof that every model or real app is safe.

## The part I want other developers to try

`GuardedToolRegistry` is my small integration point for Python apps. A developer registers a function and the arguments it accepts, then sends a model’s proposed call through the registry before running the function. The app itself must label where information came from and keep that label attached. If an app skips the registry or invents its own trusted labels from model text, this protection can’t help.

The checker handles common argument types and limits; it is not a complete JSON Schema library. Please add extra review or a person’s approval before connecting sensitive or hard-to-undo actions.

## What’s still on my to-do list

- Test the vLLM adapter against an actual vLLM server. The code path is there, but I haven’t verified it with a live server.
- Try more models and more varied attack messages.
- Work out a careful way to preserve source labels as an app combines or summarizes text.
- Add more checks as the project grows.

The Docker setup is also unverified. The Streamlit page is meant for local demos. Uploading it to Streamlit Community Cloud can show the page, but it cannot reach Ollama running on my laptop; a hosted version would need a separate, reachable model server. The app’s local task file is for demonstration, not shared or permanent storage.

If you’re reading the code, I hope the small setup makes it easy to see where a model request becomes a real tool action—and where I put the check in between.
