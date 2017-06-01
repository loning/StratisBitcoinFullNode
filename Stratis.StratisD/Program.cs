using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NBitcoin;
using NBitcoin.DataEncoders;
using NBitcoin.Protocol;
using Stratis.Bitcoin.BlockStore;
using Stratis.Bitcoin.Builder;
using Stratis.Bitcoin.Configuration;
using Stratis.Bitcoin.Consensus;
using Stratis.Bitcoin.Logging;
using Stratis.Bitcoin.MemoryPool;
using Stratis.Bitcoin.Miner;
using Stratis.Bitcoin.Utilities;
using System.Diagnostics;

namespace Stratis.StratisD
{
	

	public class Program
	{
		public class ConsoleTraceListener : TraceListener
		{
			public override void Write(string message)
			{
				Console.Write(message);
			}

			public override void WriteLine(string message)
			{
				Console.WriteLine(message);
			}
		}
        public static void Main(string[] args)
		{
			TraceSource ts = new TraceSource("NBitcoin");

			SourceSwitch sourceSwitch = new SourceSwitch("SourceSwitch", "Verbose");
			ts.Switch = sourceSwitch;
            ts.Listeners.Add(new ConsoleTraceListener());
			Console.WriteLine(ts.Listeners.Count);
            ts.TraceInformation("hello");

			var n = Network.Main;
			var loggerFactory = new LoggerFactory()
                .AddConsole(LogLevel.Debug, false);
			Logs.Configure(loggerFactory);

            var network = InitLLCoin();

			if (NodeSettings.PrintHelp(args, network))
				return;

			//var network = args.Contains("-testnet") ? InitStratisTest() : Network.StratisMain;


            var nodeSettings = NodeSettings.FromArguments(args, "stratis", network, ProtocolVersion.ALT_PROTOCOL_VERSION);

			// NOTES: running BTC and STRAT side by side is not possible yet as the flags for serialization are static

			var node = new FullNodeBuilder()
				.UseNodeSettings(nodeSettings)
				.UseStratisConsensus()
				.UseBlockStore()
				.UseMempool()
				.AddPowPosMining()
				.Build();

			Task.Delay(TimeSpan.FromMinutes(1)).ContinueWith(t =>
			{
				//TryStartPowMiner(args, node);
				//TryStartPosMiner(args, node);
			});

		    node.Run();

			
		}

		private static void TryStartPowMiner(string[] args, IFullNode node)
		{
			// mining can be called from either RPC or on start
			// to manage the on strat we need to get an address to the mining code
			var mine = args.FirstOrDefault(a => a.Contains("mine="));
			if (mine != null)
			{
				// get the address to mine to
				var addres = mine.Replace("mine=", string.Empty);
				var pubkey = BitcoinAddress.Create(addres, node.Network);
				node.Services.ServiceProvider.Service<PowMining>().Mine(pubkey.ScriptPubKey);
			}
		}

		private static void TryStartPosMiner(string[] args, IFullNode node)
		{
			// mining can be called from either RPC or on start
			// to manage the on strat we need to get an address to the mining code
			var mine = args.FirstOrDefault(a => a.Contains("mine="));
			if (mine != null)
			{
				// TODO: this will be replaced by the wallet, for now the UTXO's 
				// that can stake are manually inserted in the miner.
				var stakes = new List<PosMinting.TrxStakingInfo>()
				{
					new PosMinting.TrxStakingInfo { TransactionHash = uint256.Parse("d9f12b2e8a75bb4657b0594374559d77a8fd036e55b43809d62ebfed75de25a2"), PrvKey = Key.Parse("[output priv key]")},
					new PosMinting.TrxStakingInfo { TransactionHash = uint256.Parse("d521cf4703e726b505d06ecf37b8f20715294b9db4979e5f17414da64f01123a"), PrvKey = Key.Parse("[output priv key]")},
					new PosMinting.TrxStakingInfo { TransactionHash = uint256.Parse("d09b2576fbf9a89dc08cf1ce8ff0dee52a96fab2c7db26047717866a65e2be12"), PrvKey = Key.Parse("[output priv key]")},
					new PosMinting.TrxStakingInfo { TransactionHash = uint256.Parse("1130f0d6e45290a33f0a8525a531b005e357196d5cc40b5d781d75af5f19795f"), PrvKey = Key.Parse("[output priv key]")},
				};

				node.Services.ServiceProvider.Service<PosMinting>().Mine(stakes);
			}
		}



		private static Network InitStratisTest()
		{
			Block.BlockSignature = true;
			Transaction.TimeStamp = true;
			
			var consensus = Network.StratisMain.Consensus.Clone();
			consensus.PowLimit = new Target(uint256.Parse("0000ffff00000000000000000000000000000000000000000000000000000000"));
			
			// The message start string is designed to be unlikely to occur in normal data.
			// The characters are rarely used upper ASCII, not valid as UTF-8, and produce
			// a large 4-byte int at any alignment.
			var pchMessageStart = new byte[4];
			pchMessageStart[0] = 0x71;
			pchMessageStart[1] = 0x31;
			pchMessageStart[2] = 0x21;
			pchMessageStart[3] = 0x11;
			var magic = BitConverter.ToUInt32(pchMessageStart, 0); //0x5223570; 

			var genesis = Network.StratisMain.GetGenesis().Clone();
			genesis.Header.Time = 1493909211;
			genesis.Header.Nonce = 2433759;
			genesis.Header.Bits = consensus.PowLimit;
			consensus.HashGenesisBlock = genesis.GetHash();

			Guard.Assert(consensus.HashGenesisBlock == uint256.Parse("0x00000e246d7b73b88c9ab55f2e5e94d9e22d471def3df5ea448f5576b1d156b9"));

			var builder = new NetworkBuilder()
				.SetName("StratisTest")
				.SetConsensus(consensus)
				.SetMagic(magic)
				.SetGenesis(genesis)
				.SetPort(26178)
				.SetRPCPort(26174)
				.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] {(65)})
				.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] {(196)})
				.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] {(65 + 128)})
				.SetBase58Bytes(Base58Type.ENCRYPTED_SECRET_KEY_NO_EC, new byte[] {0x01, 0x42})
				.SetBase58Bytes(Base58Type.ENCRYPTED_SECRET_KEY_EC, new byte[] {0x01, 0x43})
				.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] {(0x04), (0x88), (0xB2), (0x1E)})
				.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] {(0x04), (0x88), (0xAD), (0xE4)})
				.AddDNSSeeds(new[]
				{
					new DNSSeedData("stratisplatform.com", "testnode1.stratisplatform.com"), 
				});

			return builder.BuildAndRegister();
		}


        private static Network InitLLCoin()
        {
            Block.BlockSignature = true;
            Transaction.TimeStamp = true;

            var consensus = Network.StratisMain.Consensus.Clone();
			consensus.PowLimit = new Target(uint256.Parse("0x000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

			// The message start string is designed to be unlikely to occur in normal data.
			// The characters are rarely used upper ASCII, not valid as UTF-8, and produce
			// a large 4-byte int at any alignment.
			var pchMessageStart = new byte[4];
            pchMessageStart[0] = 0x71;
            pchMessageStart[1] = 0x31;
            pchMessageStart[2] = 0x21;
            pchMessageStart[3] = 0x11;
            var magic = BitConverter.ToUInt32(pchMessageStart, 0); //0x5223570; 

            //var genesis = Network.StratisMain.GetGenesis().Clone();
            var genesis = CreateStratisGenesisBlock(1496069495, 1840204, consensus.PowLimit, 1, Money.Zero);
            consensus.HashGenesisBlock = genesis.GetHash();

            Guard.Assert(consensus.HashGenesisBlock == uint256.Parse("0x0002c75e4179fd8dc22391536af7e647bdd88b83d9ed57fcf09e5ae3d06cae78"));

            var builder = new NetworkBuilder()
                .SetName("LLCoin")
                .SetConsensus(consensus)
                .SetMagic(magic)
                .SetGenesis(genesis)
                .SetPort(36178)
                .SetRPCPort(36174)
                .SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { (63) })
                .SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { (125) })
                .SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { (63 + 125) })
                .SetBase58Bytes(Base58Type.ENCRYPTED_SECRET_KEY_NO_EC, new byte[] { 0x01, 0x42 })
                .SetBase58Bytes(Base58Type.ENCRYPTED_SECRET_KEY_EC, new byte[] { 0x01, 0x43 })
                .SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { (0x04), (0x88), (0xC2), (0x1E) })
                .SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { (0x04), (0x88), (0xB2), (0xDD) })
                .AddDNSSeeds(new[]
                {
                    new DNSSeedData("stratisplatform.com", "testnode1.stratisplatform.com"),
                });

            return builder.BuildAndRegister();
        }

		private static Block CreateStratisGenesisBlock(uint nTime, uint nNonce, uint nBits, int nVersion, Money genesisReward)
		{
			string pszTimestamp = "Hello Genesis";
			return CreateStratisGenesisBlock(pszTimestamp, nTime, nNonce, nBits, nVersion, genesisReward);
		}

		private static Block CreateStratisGenesisBlock(string pszTimestamp, uint nTime, uint nNonce, uint nBits, int nVersion, Money genesisReward)
		{
			Transaction txNew = new Transaction();
			txNew.Version = 1;
			txNew.Time = nTime;
            var op = Op.GetPushOp(1);
            op.Code = (OpcodeType)0x1;
            op.PushData = new[] { (byte)42 };

			txNew.AddInput(new TxIn()
			{
                
				ScriptSig = new Script(Op.GetPushOp(0), op, 
                Op.GetPushOp(Encoders.ASCII.DecodeData(pszTimestamp)))
			});
			txNew.AddOutput(new TxOut()
			{
				Value = genesisReward,
			});
			Block genesis = new Block();
			genesis.Header.BlockTime = Utils.UnixTimeToDateTime(nTime);
			genesis.Header.Bits = nBits;
			genesis.Header.Nonce = nNonce;
			genesis.Header.Version = nVersion;
			genesis.Transactions.Add(txNew);
			genesis.Header.HashPrevBlock = uint256.Zero;
			genesis.UpdateMerkleRoot();
			return genesis;
		}
	}
}
