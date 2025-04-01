package blog

import (
	"context"
	"cosmossdk.io/core/appmodule"
	"cosmossdk.io/core/store"
	"cosmossdk.io/depinject"
	"cosmossdk.io/log"
	"encoding/json"
	"fmt"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	cdctypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"io"
	"net/http"
	"strconv"
	"strings"

	// this line is used by starport scaffolding # 1

	modulev1 "blog/api/blog/blog/module"
	"blog/x/blog/keeper"
	"blog/x/blog/types"

	clienttx "github.com/cosmos/cosmos-sdk/client/tx"
)

var (
	_ module.AppModuleBasic      = (*AppModule)(nil)
	_ module.AppModuleSimulation = (*AppModule)(nil)
	_ module.HasGenesis          = (*AppModule)(nil)
	_ module.HasInvariants       = (*AppModule)(nil)
	_ module.HasConsensusVersion = (*AppModule)(nil)

	_ appmodule.AppModule       = (*AppModule)(nil)
	_ appmodule.HasBeginBlocker = (*AppModule)(nil)
	_ appmodule.HasEndBlocker   = (*AppModule)(nil)
)

// ----------------------------------------------------------------------------
// AppModuleBasic
// ----------------------------------------------------------------------------

// AppModuleBasic implements the AppModuleBasic interface that defines the
// independent methods a Cosmos SDK module needs to implement.
type AppModuleBasic struct {
	cdc codec.BinaryCodec
}

func NewAppModuleBasic(cdc codec.BinaryCodec) AppModuleBasic {
	return AppModuleBasic{cdc: cdc}
}

// Name returns the name of the module as a string.
func (AppModuleBasic) Name() string {
	return types.ModuleName
}

// RegisterLegacyAminoCodec registers the amino codec for the module, which is used
// to marshal and unmarshal structs to/from []byte in order to persist them in the module's KVStore.
func (AppModuleBasic) RegisterLegacyAminoCodec(cdc *codec.LegacyAmino) {}

// RegisterInterfaces registers a module's interface types and their concrete implementations as proto.Message.
func (a AppModuleBasic) RegisterInterfaces(reg cdctypes.InterfaceRegistry) {
	types.RegisterInterfaces(reg)
}

// DefaultGenesis returns a default GenesisState for the module, marshalled to json.RawMessage.
// The default GenesisState need to be defined by the module developer and is primarily used for testing.
func (AppModuleBasic) DefaultGenesis(cdc codec.JSONCodec) json.RawMessage {
	return cdc.MustMarshalJSON(types.DefaultGenesis())
}

// ValidateGenesis used to validate the GenesisState, given in its json.RawMessage form.
func (AppModuleBasic) ValidateGenesis(cdc codec.JSONCodec, config client.TxEncodingConfig, bz json.RawMessage) error {
	var genState types.GenesisState
	if err := cdc.UnmarshalJSON(bz, &genState); err != nil {
		return fmt.Errorf("failed to unmarshal %s genesis state: %w", types.ModuleName, err)
	}
	return genState.Validate()
}

// RegisterGRPCGatewayRoutes registers the gRPC Gateway routes for the module.
func (AppModuleBasic) RegisterGRPCGatewayRoutes(clientCtx client.Context, mux *runtime.ServeMux) {
	if err := types.RegisterQueryHandlerClient(context.Background(), mux, types.NewQueryClient(clientCtx)); err != nil {
		panic(err)
	}

	registerRESTRoutes(clientCtx, mux)

	// 이 부분은 proto 파일에 REST 어노테이션을 추가한 후에 자동 생성된 함수를 사용합니다
	//if err := types.RegisterMsgHandlerClient(context.Background(), mux, types.NewMsgClient(clientCtx)); err != nil {
	//	panic(err)
	//}
}

//	func registerRESTRoutes(clientCtx client.Context, mux *runtime.ServeMux) {
//		pattern := runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1, 2, 2}, []string{"blog", "blog", "posts"}, "", runtime.AssumeColonVerbOpt(true)))
//
//		mux.Handle("POST", pattern, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
//			// 요청 처리 로직
//			var requestBody struct {
//				Creator string `json:"creator"`
//				Title   string `json:"title"`
//				Body    string `json:"body"`
//				BaseReq struct {
//					From     string `json:"from"`
//					ChainID  string `json:"chain_id"`
//					Gas      string `json:"gas,omitempty"`
//					Memo     string `json:"memo,omitempty"`
//					Simulate bool   `json:"simulate,omitempty"`
//				} `json:"base_req"`
//			}
//
//			data, err := io.ReadAll(req.Body)
//			if err != nil {
//				http.Error(w, fmt.Sprintf("failed to read request body: %v", err), http.StatusBadRequest)
//				return
//			}
//
//			if err := json.Unmarshal(data, &requestBody); err != nil {
//				http.Error(w, fmt.Sprintf("failed to unmarshal request: %v", err), http.StatusBadRequest)
//				return
//			}
//
//			// CLI 명령 실행을 위한 로직
//			// 이 부분은 클라이언트 요청을 CLI 명령으로 변환하여 실행합니다
//			cmd := exec.Command("blogd", "tx", "blog", "create-post",
//				requestBody.Title,
//				requestBody.Body,
//				"--from", requestBody.BaseReq.From,
//				"--chain-id", requestBody.BaseReq.ChainID,
//				"--output", "json",
//				"--yes") // 자동으로 yes로 응답
//
//			output, err := cmd.CombinedOutput()
//			if err != nil {
//				http.Error(w, fmt.Sprintf("failed to execute command: %v\nOutput: %s", err, output), http.StatusInternalServerError)
//				return
//			}
//
//			w.Header().Set("Content-Type", "application/json")
//			w.Write(output)
//		})
//	}
//
//	func registerRESTRoutes(clientCtx client.Context, mux *runtime.ServeMux) {
//		pattern := runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1, 2, 2}, []string{"blog", "blog", "posts"}, "", runtime.AssumeColonVerbOpt(true)))
//
//		mux.Handle("POST", pattern, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
//			// 요청 처리 로직
//			var requestBody struct {
//				Creator string `json:"creator"`
//				Title   string `json:"title"`
//				Body    string `json:"body"`
//			}
//
//			fmt.Sprintf("value===")
//			fmt.Sprintf(requestBody.Body)
//			fmt.Sprintf(requestBody.Title)
//			fmt.Sprintf("value===")
//
//			data, err := io.ReadAll(req.Body)
//			if err != nil {
//				http.Error(w, fmt.Sprintf("failed to read request body: %v", err), http.StatusBadRequest)
//				return
//			}
//
//			if err := json.Unmarshal(data, &requestBody); err != nil {
//				http.Error(w, fmt.Sprintf("failed to unmarshal request: %v", err), http.StatusBadRequest)
//				return
//			}
//
//			// gRPC 클라이언트 생성 및 호출
//			grpcClient := types.NewMsgClient(clientCtx)
//
//			//resp, err := types.NewMsgCreatePost(requestBody.Creator,requestBody.Title,requestBody.Body)
//			//resp, err := grpcClient.CreatePost(req.Context(), &types.MsgCreatePost{
//			//	Creator: requestBody.Creator,
//			//	Title:   requestBody.Title,
//			//	Body:    requestBody.Body,
//			//})
//			resp, err := grpcClient.CreatePost(
//				context.Background(), // or req.Context() if you want to inherit HTTP context
//				&types.MsgCreatePost{
//					Creator: requestBody.Creator,
//					Title:   requestBody.Title,
//					Body:    requestBody.Body,
//				},
//			)
//
//			if err != nil {
//				http.Error(w, fmt.Sprintf("failed to call gRPC: %v"+requestBody.Title, err), http.StatusInternalServerError)
//				return
//			}
//
//			// 응답 마샬링 및 반환
//			respBytes, err := json.Marshal(resp)
//			if err != nil {
//				http.Error(w, fmt.Sprintf("failed to marshal response: %v", err), http.StatusInternalServerError)
//				return
//			}
//
//			w.Header().Set("Content-Type", "application/json")
//			w.Write(respBytes)
//		})
//	}
//func registerRESTRoutes(clientCtx client.Context, mux *runtime.ServeMux) {
//	pattern := runtime.MustPattern(runtime.NewPattern(
//		1,
//		[]int{2, 0, 2, 1, 2, 2},
//		[]string{"blog", "blog", "posts"},
//		"",
//	))
//
//	mux.Handle("POST", pattern, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
//		// 요청 구조체 정의
//		type RequestBody struct {
//			BaseReq struct {
//				From    string     `json:"from"`
//				ChainID string     `json:"chain_id"`
//				Gas     string     `json:"gas"`
//				Fees    []sdk.Coin `json:"fees"`
//				Memo    string     `json:"memo,omitempty"`
//			} `json:"base_req"`
//			Creator string `json:"creator"`
//			Title   string `json:"title"`
//			Body    string `json:"body"`
//		}
//
//		var reqBody RequestBody
//		// 요청 읽기 및 디코딩
//		body, err := io.ReadAll(req.Body)
//		if err != nil {
//			http.Error(w, fmt.Sprintf("요청 읽기 실패: %v", err), http.StatusBadRequest)
//			return
//		}
//
//		if err := json.Unmarshal(body, &reqBody); err != nil {
//			http.Error(w, fmt.Sprintf("요청 디코딩 실패: %v", err), http.StatusBadRequest)
//			return
//		}
//
//		// 필수 필드 검증
//		if reqBody.Creator == "" || reqBody.Title == "" || reqBody.Body == "" {
//			http.Error(w, "필수 필드 누락", http.StatusBadRequest)
//			return
//		}
//
//		// 클라이언트 컨텍스트 설정
//		fromAddr, err := sdk.AccAddressFromBech32(reqBody.BaseReq.From)
//		if err != nil {
//			http.Error(w, fmt.Sprintf("주소 파싱 실패: %v", err), http.StatusBadRequest)
//			return
//		}
//
//		txCtx := clientCtx.WithFromAddress(fromAddr)
//		txCtx = txCtx.WithChainID(reqBody.BaseReq.ChainID)
//
//		// 메시지 생성
//		msg := types.NewMsgCreatePost(
//			reqBody.Creator,
//			reqBody.Title,
//			reqBody.Body,
//		)
//
//		// 가스 설정
//		var gasLimit uint64
//		if reqBody.BaseReq.Gas == "auto" {
//			// 자동 가스 계산 시 기본값 사용
//			gasLimit = 200000
//		} else {
//			var err error
//			gasLimit, err = strconv.ParseUint(reqBody.BaseReq.Gas, 10, 64)
//			if err != nil {
//				http.Error(w, fmt.Sprintf("가스 값 파싱 실패: %v", err), http.StatusBadRequest)
//				return
//			}
//		}
//
//		// 트랜잭션 팩토리 설정
//		txFactory := clienttx.Factory{}.
//			WithChainID(reqBody.BaseReq.ChainID).
//			WithGas(gasLimit).
//			WithTxConfig(txCtx.TxConfig)
//
//		if len(reqBody.BaseReq.Fees) > 0 {
//			txFactory = txFactory.WithFees(sdk.Coins(reqBody.BaseReq.Fees).String())
//		}
//
//		if reqBody.BaseReq.Memo != "" {
//			txFactory = txFactory.WithMemo(reqBody.BaseReq.Memo)
//		}
//
//		// 트랜잭션 생성
//		txBuilder := txCtx.TxConfig.NewTxBuilder()
//		if err := txBuilder.SetMsgs(msg); err != nil {
//			http.Error(w, fmt.Sprintf("메시지 설정 실패: %v", err), http.StatusInternalServerError)
//			return
//		}
//
//		txBuilder.SetGasLimit(gasLimit)
//		if reqBody.BaseReq.Memo != "" {
//			txBuilder.SetMemo(reqBody.BaseReq.Memo)
//		}
//
//		if len(reqBody.BaseReq.Fees) > 0 {
//			txBuilder.SetFeeAmount(reqBody.BaseReq.Fees)
//		}
//
//		// 트랜잭션 JSON 형식으로 반환
//		// 참고: 실제 구현에서는 클라이언트가 이 트랜잭션에 서명하고 제출해야 함
//		txJSON, err := txCtx.TxConfig.TxJSONEncoder()(txBuilder.GetTx())
//		if err != nil {
//			http.Error(w, fmt.Sprintf("JSON 인코딩 실패: %v", err), http.StatusInternalServerError)
//			return
//		}
//
//		w.Header().Set("Content-Type", "application/json")
//		w.Write(txJSON)
//	})
//}

func registerRESTRoutes(clientCtx client.Context, mux *runtime.ServeMux) {
	pattern := runtime.MustPattern(runtime.NewPattern(
		1,
		[]int{2, 0, 2, 1, 2, 2},
		[]string{"blog", "blog", "posts"},
		"",
	))

	mux.Handle("POST", pattern, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		// 요청 구조체 정의
		type RequestBody struct {
			BaseReq struct {
				From    string     `json:"from"`
				ChainID string     `json:"chain_id"`
				Gas     string     `json:"gas"`
				Fees    []sdk.Coin `json:"fees"`
				Memo    string     `json:"memo,omitempty"`
			} `json:"base_req"`
			Creator string `json:"creator"`
			Title   string `json:"title"`
			Body    string `json:"body"`
		}

		var reqBody RequestBody
		// 요청 읽기 및 디코딩
		body, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("요청 읽기 실패: %v", err), http.StatusBadRequest)
			return
		}

		if err := json.Unmarshal(body, &reqBody); err != nil {
			http.Error(w, fmt.Sprintf("요청 디코딩 실패: %v", err), http.StatusBadRequest)
			return
		}

		// 필수 필드 검증
		if reqBody.Creator == "" || reqBody.Title == "" || reqBody.Body == "" {
			http.Error(w, "필수 필드 누락", http.StatusBadRequest)
			return
		}

		// 클라이언트 컨텍스트 설정
		fromAddr, err := sdk.AccAddressFromBech32(reqBody.BaseReq.From)
		if err != nil {
			http.Error(w, fmt.Sprintf("주소 파싱 실패: %v", err), http.StatusBadRequest)
			return
		}

		txCtx := clientCtx.WithFromAddress(fromAddr)
		txCtx = txCtx.WithChainID(reqBody.BaseReq.ChainID)

		// 메시지 생성
		msg := types.NewMsgCreatePost(
			reqBody.Creator,
			reqBody.Title,
			reqBody.Body,
		)

		// 가스 설정
		var gasLimit uint64
		if reqBody.BaseReq.Gas == "auto" {
			// 자동 가스 계산 시 기본값 사용
			gasLimit = 200000
		} else {
			var err error
			gasLimit, err = strconv.ParseUint(reqBody.BaseReq.Gas, 10, 64)
			if err != nil {
				http.Error(w, fmt.Sprintf("가스 값 파싱 실패: %v", err), http.StatusBadRequest)
				return
			}
		}

		// 트랜잭션 팩토리 설정
		txFactory := clienttx.Factory{}.
			WithChainID(reqBody.BaseReq.ChainID).
			WithGas(gasLimit).
			WithTxConfig(txCtx.TxConfig)

		if len(reqBody.BaseReq.Fees) > 0 {
			txFactory = txFactory.WithFees(sdk.Coins(reqBody.BaseReq.Fees).String())
		}

		if reqBody.BaseReq.Memo != "" {
			txFactory = txFactory.WithMemo(reqBody.BaseReq.Memo)
		}

		// 트랜잭션 생성
		txBuilder := txCtx.TxConfig.NewTxBuilder()
		if err := txBuilder.SetMsgs(msg); err != nil {
			http.Error(w, fmt.Sprintf("메시지 설정 실패: %v", err), http.StatusInternalServerError)
			return
		}

		txBuilder.SetGasLimit(gasLimit)
		if reqBody.BaseReq.Memo != "" {
			txBuilder.SetMemo(reqBody.BaseReq.Memo)
		}

		if len(reqBody.BaseReq.Fees) > 0 {
			txBuilder.SetFeeAmount(reqBody.BaseReq.Fees)
		}

		// 키링에서 키 가져오기
		// 키링에서 키 가져오기
		// 최신 버전 파라미터 조정
		//kr, err := keyring.New("blog", keyring.BackendTest, "~/.blog", strings.NewReader(""), clientCtx.Codec)
		//if err != nil {
		//	http.Error(w, fmt.Sprintf("키링 생성 실패: %v", err), http.StatusInternalServerError)
		//	return
		//}
		kr, err := keyring.New(
			sdk.KeyringServiceName(),
			keyring.BackendTest,
			clientCtx.HomeDir,
			strings.NewReader(""),
			clientCtx.Codec,
		)
		if err != nil {
			http.Error(w, fmt.Sprintf("키링 생성 실패: %v", err), http.StatusInternalServerError)
			return
		}

		// 계정 정보를 gRPC 쿼리로 직접 조회
		grpcConn, err := grpc.Dial(
			"localhost:9090", // gRPC 서버 주소
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err != nil {
			http.Error(w, fmt.Sprintf("gRPC 연결 실패: %v", err), http.StatusInternalServerError)
			return
		}
		defer grpcConn.Close()

		// Auth 쿼리 클라이언트 생성
		authQueryClient := authtypes.NewQueryClient(grpcConn)

		// 계정 정보 요청
		accountResp, err := authQueryClient.Account(
			context.Background(),
			&authtypes.QueryAccountRequest{Address: fromAddr.String()},
		)
		if err != nil {
			http.Error(w, fmt.Sprintf("계정 정보 조회 실패: %v", err), http.StatusInternalServerError)
			return
		}

		// 계정 정보 언마샬
		var account authtypes.AccountI
		if err := clientCtx.InterfaceRegistry.UnpackAny(accountResp.Account, &account); err != nil {
			http.Error(w, fmt.Sprintf("계정 정보 언마샬 실패: %v", err), http.StatusInternalServerError)
			return
		}

		// 계정 번호와 시퀀스 번호 가져오기
		accNum := account.GetAccountNumber()
		accSeq := account.GetSequence()

		// 트랜잭션 팩토리 설정 업데이트
		txFactory = txFactory.
			WithAccountNumber(accNum).
			WithSequence(accSeq).
			WithKeybase(kr).
			WithSignMode(signing.SignMode_SIGN_MODE_DIRECT)

		// 트랜잭션 서명
		err = clienttx.Sign(
			context.Background(), // 컨텍스트 추가
			txFactory,
			reqBody.BaseReq.From, // 키 이름
			txBuilder,
			true, // 서명 시 덮어쓰기
		)
		if err != nil {
			http.Error(w, fmt.Sprintf("트랜잭션 서명 실패: %v", err), http.StatusInternalServerError)
			return
		}

		// 서명된 트랜잭션을 바이트로 인코딩
		txBytes, err := txCtx.TxConfig.TxEncoder()(txBuilder.GetTx())
		if err != nil {
			http.Error(w, fmt.Sprintf("트랜잭션 인코딩 실패: %v", err), http.StatusInternalServerError)
			return
		}

		// 트랜잭션 브로드캐스트
		resp, err := txCtx.BroadcastTx(txBytes)
		if err != nil {
			http.Error(w, fmt.Sprintf("트랜잭션 브로드캐스트 실패: %v", err), http.StatusInternalServerError)
			return
		}

		// 응답 반환
		respBytes, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			http.Error(w, fmt.Sprintf("응답 인코딩 실패: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(respBytes)
	})
}

// ----------------------------------------------------------------------------
// AppModule
// ----------------------------------------------------------------------------

// AppModule implements the AppModule interface that defines the inter-dependent methods that modules need to implement
type AppModule struct {
	AppModuleBasic

	keeper        keeper.Keeper
	accountKeeper types.AccountKeeper
	bankKeeper    types.BankKeeper
}

func NewAppModule(
	cdc codec.Codec,
	keeper keeper.Keeper,
	accountKeeper types.AccountKeeper,
	bankKeeper types.BankKeeper,
) AppModule {
	return AppModule{
		AppModuleBasic: NewAppModuleBasic(cdc),
		keeper:         keeper,
		accountKeeper:  accountKeeper,
		bankKeeper:     bankKeeper,
	}
}

// RegisterServices registers a gRPC query service to respond to the module-specific gRPC queries
func (am AppModule) RegisterServices(cfg module.Configurator) {
	types.RegisterMsgServer(cfg.MsgServer(), keeper.NewMsgServerImpl(am.keeper))
	types.RegisterQueryServer(cfg.QueryServer(), am.keeper)

}

// RegisterInvariants registers the invariants of the module. If an invariant deviates from its predicted value, the InvariantRegistry triggers appropriate logic (most often the chain will be halted)
func (am AppModule) RegisterInvariants(_ sdk.InvariantRegistry) {}

// InitGenesis performs the module's genesis initialization. It returns no validator updates.
func (am AppModule) InitGenesis(ctx sdk.Context, cdc codec.JSONCodec, gs json.RawMessage) {
	var genState types.GenesisState
	// Initialize global index to index in genesis state
	cdc.MustUnmarshalJSON(gs, &genState)

	InitGenesis(ctx, am.keeper, genState)
}

// ExportGenesis returns the module's exported genesis state as raw JSON bytes.
func (am AppModule) ExportGenesis(ctx sdk.Context, cdc codec.JSONCodec) json.RawMessage {
	genState := ExportGenesis(ctx, am.keeper)
	return cdc.MustMarshalJSON(genState)
}

// ConsensusVersion is a sequence number for state-breaking change of the module.
// It should be incremented on each consensus-breaking change introduced by the module.
// To avoid wrong/empty versions, the initial version should be set to 1.
func (AppModule) ConsensusVersion() uint64 { return 1 }

// BeginBlock contains the logic that is automatically triggered at the beginning of each block.
// The begin block implementation is optional.
func (am AppModule) BeginBlock(_ context.Context) error {
	return nil
}

// EndBlock contains the logic that is automatically triggered at the end of each block.
// The end block implementation is optional.
func (am AppModule) EndBlock(_ context.Context) error {
	return nil
}

// IsOnePerModuleType implements the depinject.OnePerModuleType interface.
func (am AppModule) IsOnePerModuleType() {}

// IsAppModule implements the appmodule.AppModule interface.
func (am AppModule) IsAppModule() {}

// ----------------------------------------------------------------------------
// App Wiring Setup
// ----------------------------------------------------------------------------

func init() {
	appmodule.Register(
		&modulev1.Module{},
		appmodule.Provide(ProvideModule),
	)
}

type ModuleInputs struct {
	depinject.In

	StoreService store.KVStoreService
	Cdc          codec.Codec
	Config       *modulev1.Module
	Logger       log.Logger

	AccountKeeper types.AccountKeeper
	BankKeeper    types.BankKeeper
}

type ModuleOutputs struct {
	depinject.Out

	BlogKeeper keeper.Keeper
	Module     appmodule.AppModule
}

func ProvideModule(in ModuleInputs) ModuleOutputs {
	// default to governance authority if not provided
	authority := authtypes.NewModuleAddress(govtypes.ModuleName)
	if in.Config.Authority != "" {
		authority = authtypes.NewModuleAddressOrBech32Address(in.Config.Authority)
	}
	k := keeper.NewKeeper(
		in.Cdc,
		in.StoreService,
		in.Logger,
		authority.String(),
	)
	m := NewAppModule(
		in.Cdc,
		k,
		in.AccountKeeper,
		in.BankKeeper,
	)

	return ModuleOutputs{BlogKeeper: k, Module: m}
}
