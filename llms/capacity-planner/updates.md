
1 - is the "main" config.json always BF16? BF8? What is the "default" setting, and is it on the site, or in the base config.json?
2 - Default interpolate max context length from config.json.
3 - Workload overrides? Perhaps it makes sense to have some basic drop-down selections. For example:
- Average Context = 8k, 16k, 32k, 64k, 128k, 256k, 512k, 1M
- Maximum context  = 8k, 16k, 32k, 64k, 128k, 256k, 512k, 1M
- SLO Targets = 5, 10, 20, 30, 60
- KV-Cache precision should always be FP8 - just hide / suppress / remove the toggle
- Override checkpoint precision - this should have a "detected" precision (based on the input, or undetected), and an override. E.g. detected = bf16, override = FP8
At the top bar "comfortable, constrained" - remove the analytical and Level C - they are pretentious. Add colored bars and descriptions in the header / as a legend of all the possible outcomes (e.g. does not fit, constrained, comfortable) and description. 
Spacing and formatting - everything is right aligned, but deployment / KV pool / sequence is all clustered up
![[Pasted image 20260804115602.png]]


- Add B300 SXM configuration to model dropdown
Add a model drop-down menu as well , consisting of:
- all Poolside Default Models (Laguna XS.2, Laguna S.1 Laguna M.1)
- several open-source popular models (Qwen, DeepSeek, Gemma)
Validate all models render and display properly (e.g. no more "bugs" or failed fallbacks because of mixed-up architecture types such as sliding attention)
