# Shamir Secret Sharing

Neptune Core supports Shamir secret sharing to distribute shares in the wallet secret.

## How It Works

A \\(t\\)-out-of-\\(n\\) Shamir secret sharing scheme works as follows. Let \\(S \in \mathbb{F}\\) be the original secret. In the source code, we use `XFieldElement` as the field \\(\mathbb{F}\\) and `SecretKeyMaterial` as a wrapper around `XFieldElement`s when they are used for this purpose.

Sample a univariate polynomial \\(f(X)\\) of degree at most \\(t-1\\) uniformly at random except for the constant coefficient. Choose \\(S\\) for the constant coefficient, so that \\(f(0) = S\\).

With an implicit embedding \\(\mathbb{N} \rightarrow \mathbb{F}\\) we can associate the \\(i\\)th share with the point \\((i, f(i))\\). Note that \\(i=0\\) is disallowed since \\((0, f(0))\\) corresponds to the secret. To generate \\(n\\) shares we let \\(i\\) range from \\(1\\) to \\(n\\) (including the upper bound).

To reconstruct the original secret it suffices to have *any* \\(t\\) secret shares. Just reconstruct the polynomial and evaluate it at \\(0\\).

However, any selection of *fewer than \\(t\\)* secret shares contains *no information* about the original secret.

## How to Use It

First, make sure you have a wallet installed.

 - Whenever you run `neptune-core`, it will read the wallet file or create one if none is found. Unless you moved or removed this file, it is still there.
 - To test if the wallet file is present, run `neptune-cli which-wallet`.
 - To generate a wallet file without running `neptune-core`, try `neptune-cli generate-wallet`.
 - To import a wallet from a seed phrase, first make sure there is no wallet file, and then run `neptune-cli import-seed-phrase`.

To generate \\(n\\) shares in a \\(t\\)-out-of-\\(n\\) scheme, run `neptune-cli shamir-share t n` and replace `t` and `n` with the values you want. This command generates \\(n\\) seed phrases. **Note:** be sure to record the share index ("`i/n`") along with each share, as you will need this information to reconstruct the original secret.

To reconstruct the original secret, first make sure the wallet file is absent. Then run `neptune-cli shamir-combine t` and replace `t` with the same value used earlier. This command will ask you for \\(t\\) secret shares (with index) which you can supply by writing the seed phrase words of each share.

## Example

`> neptune-cli shamir-share 2 3`

```
Wallet for beta.
Read from file `[file name redacted]`.

Key share 1/3:
1. because
2. curtain
3. remove
4. marble
5. divide
6. what
7. early
8. tilt
9. debate
10. evidence
11. tag
12. ramp
13. acquire
14. side
15. tenant
16. cloud
17. nature
18. index

Key share 2/3:
1. twenty
2. pretty
3. shiver
4. position
5. panda
6. frown
7. cargo
8. target
9. country
10. deliver
11. remind
12. label
13. kick
14. call
15. exchange
16. vital
17. absent
18. barely

Key share 3/3:
1. senior
2. comfort
3. stomach
4. since
5. yard
6. dove
7. ability
8. okay
9. cloth
10. chaos
11. attack
12. enough
13. tilt
14. junk
15. risk
16. sail
17. horse
18. primary
```

```
> neptune-cli shamir-combine 2
```

```
Enter share index ("i/n"): 
1/3
Enter seed phrase for key share 1/3:
1. because
2. curtain
3. remove
4. marble
5. divide
6. what
7. early
8. tilt
9. debate
10. evidence
11. tag
12. ramp
13. acquire
14. side
15. tenant
16. cloud
17. nature
18. index

Have shares {1}/3.

Enter share index ("i/n"): 
3/3
Enter seed phrase for key share 3/3:
1. senior
2. comfort
3. stomach
4. since
5. yard
6. dove
7. ability
8. okay
9. cloth
10. chaos
11. attack
12. enough
13. tilt
14. junk 
15. risk
16. sail
17. horse
18. primary

Have shares {1,3}/3.

Shamir recombination successful.
Saving wallet to disk at [file name redacted] ...
Success.
```
