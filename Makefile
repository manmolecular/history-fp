create_zsh:  # usage: make create_zsh contact=<contact>
	python3 fp.py create --history ~/.zsh_history --contact "$(contact)"

compare_zsh:  # usage: make compare_zsh payload=<payload>
	python3 fp.py compare --history ~/.zsh_history --payload "$(payload)"

create: create_zsh  # alias, usage: make create contact=<contact>
compare: compare_zsh  # alias, usage: make compare payload=<payload>

test:
	python3 test_fp.py
