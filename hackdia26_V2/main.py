from graph.flow import build_graph

if name == "main":
    print("🚀 Lancement du LangGraph Flow...")
    graph = build_graph()
    graph.invoke(input={"email_id": "dummy-email-id"})