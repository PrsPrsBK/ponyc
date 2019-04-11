use "ponytest"
use "collections"

actor Main is TestList
  new create(env: Env) => PonyTest(env, this)
  new make() => None

  fun tag tests(test: PonyTest) =>
    test(_TestMT)
    test(_TestRandomShuffle)
    test(_TestSplitMix64)
    test(_TestXorOshiro128StarStar)
    test(_TestXorOshiro128Plus)
    test(_TestXorShift128Plus)

class iso _TestMT is UnitTest
  fun name(): String => "random/MT"

  fun apply(h: TestHelper) =>
    let mt = MT

    h.assert_eq[U64](mt.next(), 14514284786278117030)
    h.assert_eq[U64](mt.next(), 4620546740167642908)
    h.assert_eq[U64](mt.next(), 13109570281517897720)
    h.assert_eq[U64](mt.next(), 17462938647148434322)
    h.assert_eq[U64](mt.next(), 355488278567739596)
    h.assert_eq[U64](mt.next(), 7469126240319926998)
    h.assert_eq[U64](mt.next(), 4635995468481642529)
    h.assert_eq[U64](mt.next(), 418970542659199878)
    h.assert_eq[U64](mt.next(), 9604170989252516556)
    h.assert_eq[U64](mt.next(), 6358044926049913402)
    h.assert_eq[U64](mt.next(), 5058016125798318033)
    h.assert_eq[U64](mt.next(), 10349215569089701407)
    h.assert_eq[U64](mt.next(), 2583272014892537200)
    h.assert_eq[U64](mt.next(), 10032373690199166667)
    h.assert_eq[U64](mt.next(), 9627645531742285868)
    h.assert_eq[U64](mt.next(), 15810285301089087632)
    h.assert_eq[U64](mt.next(), 9219209713614924562)
    h.assert_eq[U64](mt.next(), 7736011505917826031)
    h.assert_eq[U64](mt.next(), 13729552270962724157)
    h.assert_eq[U64](mt.next(), 4596340717661012313)
    h.assert_eq[U64](mt.next(), 4413874586873285858)
    h.assert_eq[U64](mt.next(), 5904155143473820934)
    h.assert_eq[U64](mt.next(), 16795776195466785825)
    h.assert_eq[U64](mt.next(), 3040631852046752166)
    h.assert_eq[U64](mt.next(), 4529279813148173111)
    h.assert_eq[U64](mt.next(), 3658352497551999605)
    h.assert_eq[U64](mt.next(), 13205889818278417278)
    h.assert_eq[U64](mt.next(), 17853215078830450730)
    h.assert_eq[U64](mt.next(), 14193508720503142180)
    h.assert_eq[U64](mt.next(), 1488787817663097441)
    h.assert_eq[U64](mt.next(), 8484116316263611556)
    h.assert_eq[U64](mt.next(), 4745643133208116498)
    h.assert_eq[U64](mt.next(), 14333959900198994173)
    h.assert_eq[U64](mt.next(), 10770733876927207790)
    h.assert_eq[U64](mt.next(), 17529942701849009476)
    h.assert_eq[U64](mt.next(), 8081518017574486547)
    h.assert_eq[U64](mt.next(), 5945178879512507902)
    h.assert_eq[U64](mt.next(), 9821139136195250096)
    h.assert_eq[U64](mt.next(), 4728986788662773602)
    h.assert_eq[U64](mt.next(), 840062144447779464)
    h.assert_eq[U64](mt.next(), 9315169977352719788)
    h.assert_eq[U64](mt.next(), 12843335216705846126)
    h.assert_eq[U64](mt.next(), 1682692516156909696)
    h.assert_eq[U64](mt.next(), 16733405176195045732)
    h.assert_eq[U64](mt.next(), 570275675392078508)
    h.assert_eq[U64](mt.next(), 2804578118555336986)
    h.assert_eq[U64](mt.next(), 18105853946332827420)
    h.assert_eq[U64](mt.next(), 11444576169427052165)
    h.assert_eq[U64](mt.next(), 5511269538150904327)
    h.assert_eq[U64](mt.next(), 6665263661402689669)
    h.assert_eq[U64](mt.next(), 8872308438533970361)
    h.assert_eq[U64](mt.next(), 5494304472256329401)
    h.assert_eq[U64](mt.next(), 5260777597240341458)
    h.assert_eq[U64](mt.next(), 17048363385688465216)
    h.assert_eq[U64](mt.next(), 11601203342555724204)
    h.assert_eq[U64](mt.next(), 13927871433293278342)
    h.assert_eq[U64](mt.next(), 13168989862813642697)
    h.assert_eq[U64](mt.next(), 13332527631701716084)
    h.assert_eq[U64](mt.next(), 1288265801825883165)
    h.assert_eq[U64](mt.next(), 8980511589347843149)
    h.assert_eq[U64](mt.next(), 1639193574298669424)
    h.assert_eq[U64](mt.next(), 14012553476551396225)
    h.assert_eq[U64](mt.next(), 7818048564976445173)
    h.assert_eq[U64](mt.next(), 11012385938523194722)
    h.assert_eq[U64](mt.next(), 1594098091654903511)
    h.assert_eq[U64](mt.next(), 5035242355473277827)
    h.assert_eq[U64](mt.next(), 11507220397369885600)
    h.assert_eq[U64](mt.next(), 4097669440061230013)
    h.assert_eq[U64](mt.next(), 4158775797243890311)
    h.assert_eq[U64](mt.next(), 8008476757622511610)
    h.assert_eq[U64](mt.next(), 18212599999684195413)
    h.assert_eq[U64](mt.next(), 3892070972454396029)
    h.assert_eq[U64](mt.next(), 15739033291548026583)
    h.assert_eq[U64](mt.next(), 5240984520368774617)
    h.assert_eq[U64](mt.next(), 15428220128146522508)
    h.assert_eq[U64](mt.next(), 6764778500174078837)
    h.assert_eq[U64](mt.next(), 17250425930626079997)
    h.assert_eq[U64](mt.next(), 15862445320841941901)
    h.assert_eq[U64](mt.next(), 9055707723866709616)
    h.assert_eq[U64](mt.next(), 407278260229756649)
    h.assert_eq[U64](mt.next(), 6679883267401891436)
    h.assert_eq[U64](mt.next(), 13585010976506536654)
    h.assert_eq[U64](mt.next(), 9580697194899010248)
    h.assert_eq[U64](mt.next(), 7802093638911637786)
    h.assert_eq[U64](mt.next(), 535562807229422763)
    h.assert_eq[U64](mt.next(), 16772549087470588412)
    h.assert_eq[U64](mt.next(), 2069348082463192648)
    h.assert_eq[U64](mt.next(), 18080878539236249869)
    h.assert_eq[U64](mt.next(), 12688200000096479737)
    h.assert_eq[U64](mt.next(), 8989665349769173357)
    h.assert_eq[U64](mt.next(), 13575112928849473200)
    h.assert_eq[U64](mt.next(), 10859033464356012248)
    h.assert_eq[U64](mt.next(), 9748216112997718693)
    h.assert_eq[U64](mt.next(), 8405158063935141693)
    h.assert_eq[U64](mt.next(), 15279502632583570477)
    h.assert_eq[U64](mt.next(), 16055899490125284200)
    h.assert_eq[U64](mt.next(), 9066388900883848980)
    h.assert_eq[U64](mt.next(), 17884680971936629565)
    h.assert_eq[U64](mt.next(), 16395391805201036549)
    h.assert_eq[U64](mt.next(), 2550532686790805254)

    for i in Range(0, 99_900) do
      mt.next()
    end

    h.assert_eq[U64](mt.next(), 7605900683918645917)
    h.assert_eq[U64](mt.next(), 9082641531226583590)
    h.assert_eq[U64](mt.next(), 4446454406775736720)
    h.assert_eq[U64](mt.next(), 9019442596657776185)
    h.assert_eq[U64](mt.next(), 17043085403676952795)
    h.assert_eq[U64](mt.next(), 10750583492598771765)
    h.assert_eq[U64](mt.next(), 8766909389370798241)
    h.assert_eq[U64](mt.next(), 10757962449875451582)
    h.assert_eq[U64](mt.next(), 2880516476182219486)
    h.assert_eq[U64](mt.next(), 17497489511162918862)
    h.assert_eq[U64](mt.next(), 4652612098447759469)
    h.assert_eq[U64](mt.next(), 9788576916539342134)
    h.assert_eq[U64](mt.next(), 5567050575798592167)
    h.assert_eq[U64](mt.next(), 5194207919403316399)
    h.assert_eq[U64](mt.next(), 15032997032135890055)
    h.assert_eq[U64](mt.next(), 14880809409692251371)
    h.assert_eq[U64](mt.next(), 10057620390207452751)
    h.assert_eq[U64](mt.next(), 3589756813643207870)
    h.assert_eq[U64](mt.next(), 13889083130619289432)
    h.assert_eq[U64](mt.next(), 272745112352357310)
    h.assert_eq[U64](mt.next(), 11178539652074856297)
    h.assert_eq[U64](mt.next(), 16314690616693654756)
    h.assert_eq[U64](mt.next(), 3789645449173113079)
    h.assert_eq[U64](mt.next(), 16675157539333942952)
    h.assert_eq[U64](mt.next(), 4034190858635838858)
    h.assert_eq[U64](mt.next(), 6260802487971169993)
    h.assert_eq[U64](mt.next(), 6822749284157193377)
    h.assert_eq[U64](mt.next(), 8904408327694637063)
    h.assert_eq[U64](mt.next(), 15535505221714557628)
    h.assert_eq[U64](mt.next(), 5547487687172469426)
    h.assert_eq[U64](mt.next(), 13056070269860320791)
    h.assert_eq[U64](mt.next(), 2705262781620809067)
    h.assert_eq[U64](mt.next(), 13524413588062947750)
    h.assert_eq[U64](mt.next(), 10834416931589804263)
    h.assert_eq[U64](mt.next(), 14605293737057535441)
    h.assert_eq[U64](mt.next(), 17039811811587377862)
    h.assert_eq[U64](mt.next(), 7682968339787147869)
    h.assert_eq[U64](mt.next(), 14200706813048696725)
    h.assert_eq[U64](mt.next(), 1127203286209114413)
    h.assert_eq[U64](mt.next(), 1828635882727826260)
    h.assert_eq[U64](mt.next(), 16072198020477263416)
    h.assert_eq[U64](mt.next(), 3476828275180841214)
    h.assert_eq[U64](mt.next(), 3415059745294571133)
    h.assert_eq[U64](mt.next(), 12390075763023731411)
    h.assert_eq[U64](mt.next(), 12821683970668583828)
    h.assert_eq[U64](mt.next(), 15035264998720429712)
    h.assert_eq[U64](mt.next(), 13343368223434607628)
    h.assert_eq[U64](mt.next(), 11184197176988767742)
    h.assert_eq[U64](mt.next(), 7981621767396144921)
    h.assert_eq[U64](mt.next(), 10771016479996691013)
    h.assert_eq[U64](mt.next(), 12740146709185761722)
    h.assert_eq[U64](mt.next(), 5235026611214084854)
    h.assert_eq[U64](mt.next(), 7369043485092144952)
    h.assert_eq[U64](mt.next(), 807043701877401954)
    h.assert_eq[U64](mt.next(), 2338644419818827273)
    h.assert_eq[U64](mt.next(), 9888203154292991641)
    h.assert_eq[U64](mt.next(), 2261653117643492485)
    h.assert_eq[U64](mt.next(), 5827326658441138578)
    h.assert_eq[U64](mt.next(), 11857334527455096890)
    h.assert_eq[U64](mt.next(), 397976095012923257)
    h.assert_eq[U64](mt.next(), 786935492213680728)
    h.assert_eq[U64](mt.next(), 15145016570572810241)
    h.assert_eq[U64](mt.next(), 16693046664509877317)
    h.assert_eq[U64](mt.next(), 4469688630072297166)
    h.assert_eq[U64](mt.next(), 16852264890754272837)
    h.assert_eq[U64](mt.next(), 10873256733098650489)
    h.assert_eq[U64](mt.next(), 18237499023831144029)
    h.assert_eq[U64](mt.next(), 12689094313769948755)
    h.assert_eq[U64](mt.next(), 16668849730807192278)
    h.assert_eq[U64](mt.next(), 5724975183057534569)
    h.assert_eq[U64](mt.next(), 14081360411773564229)
    h.assert_eq[U64](mt.next(), 9767994113773272433)
    h.assert_eq[U64](mt.next(), 16994832643310446423)
    h.assert_eq[U64](mt.next(), 4335576382385340662)
    h.assert_eq[U64](mt.next(), 15014369649689583493)
    h.assert_eq[U64](mt.next(), 12667159483536863711)
    h.assert_eq[U64](mt.next(), 5549708033839062648)
    h.assert_eq[U64](mt.next(), 11657822633531893163)
    h.assert_eq[U64](mt.next(), 5738085579509752874)
    h.assert_eq[U64](mt.next(), 10394747297692966443)
    h.assert_eq[U64](mt.next(), 16329606558442850359)
    h.assert_eq[U64](mt.next(), 1894710846649003832)
    h.assert_eq[U64](mt.next(), 11343725437937446650)
    h.assert_eq[U64](mt.next(), 5305131412870654418)
    h.assert_eq[U64](mt.next(), 12186346816181683428)
    h.assert_eq[U64](mt.next(), 14875561156071381837)
    h.assert_eq[U64](mt.next(), 5531011851350151710)
    h.assert_eq[U64](mt.next(), 3592251877644328041)
    h.assert_eq[U64](mt.next(), 11745537505640142816)
    h.assert_eq[U64](mt.next(), 13393275255495585510)
    h.assert_eq[U64](mt.next(), 13417659807363630293)
    h.assert_eq[U64](mt.next(), 15505855752870839099)
    h.assert_eq[U64](mt.next(), 18235904804026217331)
    h.assert_eq[U64](mt.next(), 9607691439209994269)
    h.assert_eq[U64](mt.next(), 5690900333252490942)
    h.assert_eq[U64](mt.next(), 13835138359983724039)
    h.assert_eq[U64](mt.next(), 9716639646840313260)
    h.assert_eq[U64](mt.next(), 12977877641513765020)
    h.assert_eq[U64](mt.next(), 1395685694494152690)
    h.assert_eq[U64](mt.next(), 3117577794082200174)

class iso _TestRandomShuffle is UnitTest
  fun name(): String => "random/Random.shuffle"

  fun apply(h: TestHelper) ? =>
    let mt = MT
    let words: Array[String] ref =
      "a quick brown fox jumps over the lazy dog".split(" ")

    mt.shuffle[String](words)
    h.assert_eq[String](words(0)?, "fox")
    h.assert_eq[String](words(1)?, "dog")
    h.assert_eq[String](words(2)?, "the")
    h.assert_eq[String](words(3)?, "quick")
    h.assert_eq[String](words(4)?, "a")
    h.assert_eq[String](words(5)?, "over")
    h.assert_eq[String](words(6)?, "jumps")
    h.assert_eq[String](words(7)?, "brown")
    h.assert_eq[String](words(8)?, "lazy")

class iso _TestXorOshiro128StarStar is UnitTest
  fun name(): String => "random/xoroshiro128**"

  fun apply(h: TestHelper) =>
    let xoroshiro128 = XorOshiro128StarStar(5489)
    h.assert_eq[U64](xoroshiro128.next(), 529225608228480)
    h.assert_eq[U64](xoroshiro128.next(), 15850030211201659252)
    h.assert_eq[U64](xoroshiro128.next(), 9357596849517164522)
    h.assert_eq[U64](xoroshiro128.next(), 10997523097356226227)
    h.assert_eq[U64](xoroshiro128.next(), 18003803393284338686)
    h.assert_eq[U64](xoroshiro128.next(), 9604916003106123277)
    h.assert_eq[U64](xoroshiro128.next(), 11186498734383295331)
    h.assert_eq[U64](xoroshiro128.next(), 5020061622940627449)
    h.assert_eq[U64](xoroshiro128.next(), 11123765600358570747)
    h.assert_eq[U64](xoroshiro128.next(), 35382852173578092)
    h.assert_eq[U64](xoroshiro128.next(), 17939861966826083899)
    h.assert_eq[U64](xoroshiro128.next(), 11691498819241822370)
    h.assert_eq[U64](xoroshiro128.next(), 11548452810948701159)
    h.assert_eq[U64](xoroshiro128.next(), 1024306439173959681)
    h.assert_eq[U64](xoroshiro128.next(), 5247191033262280183)
    h.assert_eq[U64](xoroshiro128.next(), 2355164583649388039)
    h.assert_eq[U64](xoroshiro128.next(), 1926343922995079278)
    h.assert_eq[U64](xoroshiro128.next(), 12292016787599651474)
    h.assert_eq[U64](xoroshiro128.next(), 9671157412281638724)
    h.assert_eq[U64](xoroshiro128.next(), 6727736136218630396)
    h.assert_eq[U64](xoroshiro128.next(), 404400926230884678)
    h.assert_eq[U64](xoroshiro128.next(), 1223224451566310513)
    h.assert_eq[U64](xoroshiro128.next(), 13957601124289858516)
    h.assert_eq[U64](xoroshiro128.next(), 13107053030569361511)
    h.assert_eq[U64](xoroshiro128.next(), 1429088936208258126)
    h.assert_eq[U64](xoroshiro128.next(), 7876277269530713104)
    h.assert_eq[U64](xoroshiro128.next(), 6144728745226262988)
    h.assert_eq[U64](xoroshiro128.next(), 13655015632066339264)
    h.assert_eq[U64](xoroshiro128.next(), 9357488621537172970)
    h.assert_eq[U64](xoroshiro128.next(), 6276133910081430791)
    h.assert_eq[U64](xoroshiro128.next(), 17235064977149394186)
    h.assert_eq[U64](xoroshiro128.next(), 15365910576567428375)
    h.assert_eq[U64](xoroshiro128.next(), 304106630836101333)
    h.assert_eq[U64](xoroshiro128.next(), 16764800942517579234)
    h.assert_eq[U64](xoroshiro128.next(), 2070995749608978624)
    h.assert_eq[U64](xoroshiro128.next(), 9407519047475363212)
    h.assert_eq[U64](xoroshiro128.next(), 17004283549150454346)
    h.assert_eq[U64](xoroshiro128.next(), 11231172546717718690)
    h.assert_eq[U64](xoroshiro128.next(), 3406927787526733037)
    h.assert_eq[U64](xoroshiro128.next(), 15593854001885082958)
    h.assert_eq[U64](xoroshiro128.next(), 4818039066560779578)
    h.assert_eq[U64](xoroshiro128.next(), 14960985826767073227)
    h.assert_eq[U64](xoroshiro128.next(), 10127178920955706610)
    h.assert_eq[U64](xoroshiro128.next(), 18077992811689010120)
    h.assert_eq[U64](xoroshiro128.next(), 985034781308688696)
    h.assert_eq[U64](xoroshiro128.next(), 7207757054268460611)
    h.assert_eq[U64](xoroshiro128.next(), 7876956570475414660)
    h.assert_eq[U64](xoroshiro128.next(), 2693057249179949121)
    h.assert_eq[U64](xoroshiro128.next(), 16501086204114897738)
    h.assert_eq[U64](xoroshiro128.next(), 16276156070023507963)
    h.assert_eq[U64](xoroshiro128.next(), 6551553651815871171)
    h.assert_eq[U64](xoroshiro128.next(), 340386376459059879)
    h.assert_eq[U64](xoroshiro128.next(), 6397980007020238872)
    h.assert_eq[U64](xoroshiro128.next(), 7555181253674417024)
    h.assert_eq[U64](xoroshiro128.next(), 507093465402752020)
    h.assert_eq[U64](xoroshiro128.next(), 1279671107960701656)
    h.assert_eq[U64](xoroshiro128.next(), 10226442975868036359)
    h.assert_eq[U64](xoroshiro128.next(), 10303138444841321012)
    h.assert_eq[U64](xoroshiro128.next(), 13070827466053967360)
    h.assert_eq[U64](xoroshiro128.next(), 3621957381445725410)
    h.assert_eq[U64](xoroshiro128.next(), 14916828401443214244)
    h.assert_eq[U64](xoroshiro128.next(), 11643802617984305438)
    h.assert_eq[U64](xoroshiro128.next(), 10701461038423395290)
    h.assert_eq[U64](xoroshiro128.next(), 3941509101759635536)
    h.assert_eq[U64](xoroshiro128.next(), 1803464092225906361)
    h.assert_eq[U64](xoroshiro128.next(), 5440480724373942876)
    h.assert_eq[U64](xoroshiro128.next(), 6212872465584571359)
    h.assert_eq[U64](xoroshiro128.next(), 17622809686168328048)
    h.assert_eq[U64](xoroshiro128.next(), 3525063570414359379)
    h.assert_eq[U64](xoroshiro128.next(), 11505772870970230403)
    h.assert_eq[U64](xoroshiro128.next(), 10883074072961830034)
    h.assert_eq[U64](xoroshiro128.next(), 8988869862728169345)
    h.assert_eq[U64](xoroshiro128.next(), 5062166554076538217)
    h.assert_eq[U64](xoroshiro128.next(), 3123303918908460381)
    h.assert_eq[U64](xoroshiro128.next(), 4839283964476217)
    h.assert_eq[U64](xoroshiro128.next(), 7623289292936997184)
    h.assert_eq[U64](xoroshiro128.next(), 23584807202002928)
    h.assert_eq[U64](xoroshiro128.next(), 129050224385759582)
    h.assert_eq[U64](xoroshiro128.next(), 17581549207620631999)
    h.assert_eq[U64](xoroshiro128.next(), 585275604946675639)
    h.assert_eq[U64](xoroshiro128.next(), 11576564841320526298)
    h.assert_eq[U64](xoroshiro128.next(), 16179169443527338680)
    h.assert_eq[U64](xoroshiro128.next(), 11722436768119746692)
    h.assert_eq[U64](xoroshiro128.next(), 1029819468496759846)
    h.assert_eq[U64](xoroshiro128.next(), 7416166422649600732)
    h.assert_eq[U64](xoroshiro128.next(), 3446843700030973206)
    h.assert_eq[U64](xoroshiro128.next(), 101938466412214750)
    h.assert_eq[U64](xoroshiro128.next(), 6974277810256237698)
    h.assert_eq[U64](xoroshiro128.next(), 4080302317609285092)
    h.assert_eq[U64](xoroshiro128.next(), 2633797002080225012)
    h.assert_eq[U64](xoroshiro128.next(), 5919323799225359587)
    h.assert_eq[U64](xoroshiro128.next(), 4595144863584899221)
    h.assert_eq[U64](xoroshiro128.next(), 17048788788598366470)
    h.assert_eq[U64](xoroshiro128.next(), 422712305234666360)
    h.assert_eq[U64](xoroshiro128.next(), 14603553923101322974)
    h.assert_eq[U64](xoroshiro128.next(), 12353804611490036690)
    h.assert_eq[U64](xoroshiro128.next(), 1393404176208125697)
    h.assert_eq[U64](xoroshiro128.next(), 13375816837716530149)
    h.assert_eq[U64](xoroshiro128.next(), 3536320040830893476)

class iso _TestSplitMix64 is UnitTest
  """
  Testing the first 100 values
  against values from the C implementation with the same seed.
  """
  fun name(): String => "random/splitmix64"

  fun apply(h: TestHelper)  =>
    let splitmix64 = SplitMix64(5489)
    h.assert_eq[U64](splitmix64.next(), 5183234112540571401)
    h.assert_eq[U64](splitmix64.next(), 14437663437342183808)
    h.assert_eq[U64](splitmix64.next(), 596341932088419566)
    h.assert_eq[U64](splitmix64.next(), 9332709042398690341)
    h.assert_eq[U64](splitmix64.next(), 5229048089717964764)
    h.assert_eq[U64](splitmix64.next(), 16532330903182364361)
    h.assert_eq[U64](splitmix64.next(), 9826713873691992391)
    h.assert_eq[U64](splitmix64.next(), 14862136012064455667)
    h.assert_eq[U64](splitmix64.next(), 2685464912703271094)
    h.assert_eq[U64](splitmix64.next(), 3645772103803260546)
    h.assert_eq[U64](splitmix64.next(), 6019813842592834638)
    h.assert_eq[U64](splitmix64.next(), 7179236143568957898)
    h.assert_eq[U64](splitmix64.next(), 2934404946781234183)
    h.assert_eq[U64](splitmix64.next(), 8769194610253095596)
    h.assert_eq[U64](splitmix64.next(), 17450843410501522442)
    h.assert_eq[U64](splitmix64.next(), 8039980958295485756)
    h.assert_eq[U64](splitmix64.next(), 8514428444509011810)
    h.assert_eq[U64](splitmix64.next(), 538139499411141275)
    h.assert_eq[U64](splitmix64.next(), 9822963121437601275)
    h.assert_eq[U64](splitmix64.next(), 5883730003989896622)
    h.assert_eq[U64](splitmix64.next(), 1182331512990122538)
    h.assert_eq[U64](splitmix64.next(), 9477515008270539643)
    h.assert_eq[U64](splitmix64.next(), 6938349144887160720)
    h.assert_eq[U64](splitmix64.next(), 18323925124550400472)
    h.assert_eq[U64](splitmix64.next(), 7865987509480186040)
    h.assert_eq[U64](splitmix64.next(), 15691828006419643509)
    h.assert_eq[U64](splitmix64.next(), 15263105092434351509)
    h.assert_eq[U64](splitmix64.next(), 6203394668241302505)
    h.assert_eq[U64](splitmix64.next(), 5565571470014582859)
    h.assert_eq[U64](splitmix64.next(), 134923786752690190)
    h.assert_eq[U64](splitmix64.next(), 401978882760270155)
    h.assert_eq[U64](splitmix64.next(), 12637664923519544720)
    h.assert_eq[U64](splitmix64.next(), 13616278705605132425)
    h.assert_eq[U64](splitmix64.next(), 5897511348950472745)
    h.assert_eq[U64](splitmix64.next(), 2977589896125213059)
    h.assert_eq[U64](splitmix64.next(), 9705103796814115951)
    h.assert_eq[U64](splitmix64.next(), 16325422431042683590)
    h.assert_eq[U64](splitmix64.next(), 15938927346455353294)
    h.assert_eq[U64](splitmix64.next(), 16964849339819129518)
    h.assert_eq[U64](splitmix64.next(), 5694212752808175220)
    h.assert_eq[U64](splitmix64.next(), 12695569934510604136)
    h.assert_eq[U64](splitmix64.next(), 295660526826330716)
    h.assert_eq[U64](splitmix64.next(), 8357020042021521105)
    h.assert_eq[U64](splitmix64.next(), 16484308541176126710)
    h.assert_eq[U64](splitmix64.next(), 9107787860384746667)
    h.assert_eq[U64](splitmix64.next(), 15468360844150581622)
    h.assert_eq[U64](splitmix64.next(), 6512628197136931309)
    h.assert_eq[U64](splitmix64.next(), 7696970965719893028)
    h.assert_eq[U64](splitmix64.next(), 4855183890918837955)
    h.assert_eq[U64](splitmix64.next(), 12167369161799632782)
    h.assert_eq[U64](splitmix64.next(), 12811028718745621096)
    h.assert_eq[U64](splitmix64.next(), 14155215903390394259)
    h.assert_eq[U64](splitmix64.next(), 1042328323405863535)
    h.assert_eq[U64](splitmix64.next(), 3304213186995704081)
    h.assert_eq[U64](splitmix64.next(), 7638783428785220377)
    h.assert_eq[U64](splitmix64.next(), 5928504936383750491)
    h.assert_eq[U64](splitmix64.next(), 5405513733688087193)
    h.assert_eq[U64](splitmix64.next(), 9211843396566439816)
    h.assert_eq[U64](splitmix64.next(), 6997453020907122750)
    h.assert_eq[U64](splitmix64.next(), 7084390036270360780)
    h.assert_eq[U64](splitmix64.next(), 18212266097656238256)
    h.assert_eq[U64](splitmix64.next(), 12393273699549693704)
    h.assert_eq[U64](splitmix64.next(), 3288667150653129654)
    h.assert_eq[U64](splitmix64.next(), 8007477048063105968)
    h.assert_eq[U64](splitmix64.next(), 10512089571234430905)
    h.assert_eq[U64](splitmix64.next(), 12069607383323694956)
    h.assert_eq[U64](splitmix64.next(), 13420545457601464883)
    h.assert_eq[U64](splitmix64.next(), 4765774265693899532)
    h.assert_eq[U64](splitmix64.next(), 1592111246542771203)
    h.assert_eq[U64](splitmix64.next(), 16544262072198079842)
    h.assert_eq[U64](splitmix64.next(), 2062285129803081238)
    h.assert_eq[U64](splitmix64.next(), 16527792681914806442)
    h.assert_eq[U64](splitmix64.next(), 8599462122832398526)
    h.assert_eq[U64](splitmix64.next(), 10159948606613438204)
    h.assert_eq[U64](splitmix64.next(), 8859943296182726421)
    h.assert_eq[U64](splitmix64.next(), 6444839400569351126)
    h.assert_eq[U64](splitmix64.next(), 11811390644592918929)
    h.assert_eq[U64](splitmix64.next(), 1144192053723934299)
    h.assert_eq[U64](splitmix64.next(), 9345091692472300589)
    h.assert_eq[U64](splitmix64.next(), 8574383868647315360)
    h.assert_eq[U64](splitmix64.next(), 17369633640649596236)
    h.assert_eq[U64](splitmix64.next(), 976807420489868875)
    h.assert_eq[U64](splitmix64.next(), 4984030132859227710)
    h.assert_eq[U64](splitmix64.next(), 79896507905532042)
    h.assert_eq[U64](splitmix64.next(), 6688059646127327830)
    h.assert_eq[U64](splitmix64.next(), 16099257696905884608)
    h.assert_eq[U64](splitmix64.next(), 13325146159389358645)
    h.assert_eq[U64](splitmix64.next(), 3762556451509581745)
    h.assert_eq[U64](splitmix64.next(), 7025050101873099013)
    h.assert_eq[U64](splitmix64.next(), 9034838180199323201)
    h.assert_eq[U64](splitmix64.next(), 10252248271206836273)
    h.assert_eq[U64](splitmix64.next(), 18359549040942064633)
    h.assert_eq[U64](splitmix64.next(), 8314840975051032953)
    h.assert_eq[U64](splitmix64.next(), 6053708056417243630)
    h.assert_eq[U64](splitmix64.next(), 14566698763183337583)
    h.assert_eq[U64](splitmix64.next(), 86251419066781326)
    h.assert_eq[U64](splitmix64.next(), 3072319170459716788)
    h.assert_eq[U64](splitmix64.next(), 2556254951108643214)
    h.assert_eq[U64](splitmix64.next(), 294447012135918062)
    h.assert_eq[U64](splitmix64.next(), 8011763185713273331)

class iso _TestXorOshiro128Plus is UnitTest
  fun name(): String => "random/xoroshiro128+"

  fun apply(h: TestHelper)  =>
    let xoroshiro128 = XorOshiro128Plus(5489)
    h.assert_eq[U64](xoroshiro128.next(), 754494295053681)
    h.assert_eq[U64](xoroshiro128.next(), 5293534346078444573)
    h.assert_eq[U64](xoroshiro128.next(), 8915597671068479110)
    h.assert_eq[U64](xoroshiro128.next(), 12012535986844336436)
    h.assert_eq[U64](xoroshiro128.next(), 12008605283087592713)
    h.assert_eq[U64](xoroshiro128.next(), 17862972326796445778)
    h.assert_eq[U64](xoroshiro128.next(), 7980826805698429147)
    h.assert_eq[U64](xoroshiro128.next(), 14403948914152265609)
    h.assert_eq[U64](xoroshiro128.next(), 4977927085545555504)
    h.assert_eq[U64](xoroshiro128.next(), 7803518024886380806)
    h.assert_eq[U64](xoroshiro128.next(), 11392535447740297313)
    h.assert_eq[U64](xoroshiro128.next(), 17850833743066702059)
    h.assert_eq[U64](xoroshiro128.next(), 2735022077666827338)
    h.assert_eq[U64](xoroshiro128.next(), 8000462538329350643)
    h.assert_eq[U64](xoroshiro128.next(), 12739003499875098849)
    h.assert_eq[U64](xoroshiro128.next(), 6084477722184905794)
    h.assert_eq[U64](xoroshiro128.next(), 14225035248290297691)
    h.assert_eq[U64](xoroshiro128.next(), 7901425392536348529)
    h.assert_eq[U64](xoroshiro128.next(), 12843467781276613417)
    h.assert_eq[U64](xoroshiro128.next(), 11051424341942060340)
    h.assert_eq[U64](xoroshiro128.next(), 1485907578319965590)
    h.assert_eq[U64](xoroshiro128.next(), 14058360576000541881)
    h.assert_eq[U64](xoroshiro128.next(), 6889657892928009871)
    h.assert_eq[U64](xoroshiro128.next(), 4877118756179383709)
    h.assert_eq[U64](xoroshiro128.next(), 4291253183264326399)
    h.assert_eq[U64](xoroshiro128.next(), 12494896141227218489)
    h.assert_eq[U64](xoroshiro128.next(), 3236278287767311096)
    h.assert_eq[U64](xoroshiro128.next(), 7228353935213484399)
    h.assert_eq[U64](xoroshiro128.next(), 4356076039545090231)
    h.assert_eq[U64](xoroshiro128.next(), 9962781289779248367)
    h.assert_eq[U64](xoroshiro128.next(), 12056398173002297348)
    h.assert_eq[U64](xoroshiro128.next(), 7096073734333221568)
    h.assert_eq[U64](xoroshiro128.next(), 12458812754959358784)
    h.assert_eq[U64](xoroshiro128.next(), 8912928339273361024)
    h.assert_eq[U64](xoroshiro128.next(), 8553413690634672382)
    h.assert_eq[U64](xoroshiro128.next(), 17991119929315275760)
    h.assert_eq[U64](xoroshiro128.next(), 3678546922069508018)
    h.assert_eq[U64](xoroshiro128.next(), 12150798459195994544)
    h.assert_eq[U64](xoroshiro128.next(), 13389591837802318442)
    h.assert_eq[U64](xoroshiro128.next(), 12538661668964779510)
    h.assert_eq[U64](xoroshiro128.next(), 3027352649946568288)
    h.assert_eq[U64](xoroshiro128.next(), 1296255310218603530)
    h.assert_eq[U64](xoroshiro128.next(), 17030188702936596951)
    h.assert_eq[U64](xoroshiro128.next(), 9657172267442369130)
    h.assert_eq[U64](xoroshiro128.next(), 9755727521790770988)
    h.assert_eq[U64](xoroshiro128.next(), 16817808445525886018)
    h.assert_eq[U64](xoroshiro128.next(), 6179390321030950496)
    h.assert_eq[U64](xoroshiro128.next(), 13808073410308437376)
    h.assert_eq[U64](xoroshiro128.next(), 11705800558216558972)
    h.assert_eq[U64](xoroshiro128.next(), 11925834228590881931)
    h.assert_eq[U64](xoroshiro128.next(), 2630537697762494839)
    h.assert_eq[U64](xoroshiro128.next(), 7686835714798925555)
    h.assert_eq[U64](xoroshiro128.next(), 8357782219669860453)
    h.assert_eq[U64](xoroshiro128.next(), 10794139307459172330)
    h.assert_eq[U64](xoroshiro128.next(), 13221970255196097659)
    h.assert_eq[U64](xoroshiro128.next(), 15289467252005372135)
    h.assert_eq[U64](xoroshiro128.next(), 8552196300351744279)
    h.assert_eq[U64](xoroshiro128.next(), 16903246356285842806)
    h.assert_eq[U64](xoroshiro128.next(), 1127276477924794890)
    h.assert_eq[U64](xoroshiro128.next(), 13139032923379508129)
    h.assert_eq[U64](xoroshiro128.next(), 5532621219923309713)
    h.assert_eq[U64](xoroshiro128.next(), 17300886815428296226)
    h.assert_eq[U64](xoroshiro128.next(), 3754532190087054002)
    h.assert_eq[U64](xoroshiro128.next(), 9480422353731084820)
    h.assert_eq[U64](xoroshiro128.next(), 7589614876015212153)
    h.assert_eq[U64](xoroshiro128.next(), 16740265782842760337)
    h.assert_eq[U64](xoroshiro128.next(), 12103223263819740107)
    h.assert_eq[U64](xoroshiro128.next(), 15282901353725089224)
    h.assert_eq[U64](xoroshiro128.next(), 459835795979392179)
    h.assert_eq[U64](xoroshiro128.next(), 10418793052655850726)
    h.assert_eq[U64](xoroshiro128.next(), 8961112932215897254)
    h.assert_eq[U64](xoroshiro128.next(), 3630651923506970866)
    h.assert_eq[U64](xoroshiro128.next(), 10246238142040653898)
    h.assert_eq[U64](xoroshiro128.next(), 581944067351682717)
    h.assert_eq[U64](xoroshiro128.next(), 10514692941741054230)
    h.assert_eq[U64](xoroshiro128.next(), 18253367247039905239)
    h.assert_eq[U64](xoroshiro128.next(), 552635611622097191)
    h.assert_eq[U64](xoroshiro128.next(), 11439466253652841561)
    h.assert_eq[U64](xoroshiro128.next(), 196240131352152995)
    h.assert_eq[U64](xoroshiro128.next(), 16128733423787270993)
    h.assert_eq[U64](xoroshiro128.next(), 13378359389676057690)
    h.assert_eq[U64](xoroshiro128.next(), 16976897048457860391)
    h.assert_eq[U64](xoroshiro128.next(), 16170970326892696798)
    h.assert_eq[U64](xoroshiro128.next(), 13640577487829050804)
    h.assert_eq[U64](xoroshiro128.next(), 8283032477323093546)
    h.assert_eq[U64](xoroshiro128.next(), 18322153834526588490)
    h.assert_eq[U64](xoroshiro128.next(), 5426831254241798982)
    h.assert_eq[U64](xoroshiro128.next(), 9404185407049325057)
    h.assert_eq[U64](xoroshiro128.next(), 8681419196849741045)
    h.assert_eq[U64](xoroshiro128.next(), 10011526391222100373)
    h.assert_eq[U64](xoroshiro128.next(), 9643914075469520320)
    h.assert_eq[U64](xoroshiro128.next(), 10658662051948765028)
    h.assert_eq[U64](xoroshiro128.next(), 13454586071613229544)
    h.assert_eq[U64](xoroshiro128.next(), 6462234032373521203)
    h.assert_eq[U64](xoroshiro128.next(), 4259096558194355219)
    h.assert_eq[U64](xoroshiro128.next(), 4289286070502351611)
    h.assert_eq[U64](xoroshiro128.next(), 6864439493190003509)
    h.assert_eq[U64](xoroshiro128.next(), 13187991811993606697)
    h.assert_eq[U64](xoroshiro128.next(), 16201330389507750660)
    h.assert_eq[U64](xoroshiro128.next(), 3565034805594144162)

class iso _TestXorShift128Plus is UnitTest
  fun name(): String => "random/xorshift128+"
  fun apply(h: TestHelper) =>
    let xorshift128 = XorShift128Plus(5489)
    h.assert_eq[U64](xorshift128.next(), 46045248337)
    h.assert_eq[U64](xorshift128.next(), 92975753692)
    h.assert_eq[U64](xorshift128.next(), 386254129800057657)
    h.assert_eq[U64](xorshift128.next(), 386254129841169375)
    h.assert_eq[U64](xorshift128.next(), 420000464367209)
    h.assert_eq[U64](xorshift128.next(), 394110765257535990)
    h.assert_eq[U64](xorshift128.next(), 130579518084256993)
    h.assert_eq[U64](xorshift128.next(), 2349013512809254283)
    h.assert_eq[U64](xorshift128.next(), 3705079160155576169)
    h.assert_eq[U64](xorshift128.next(), 1015365982376536955)
    h.assert_eq[U64](xorshift128.next(), 17136068145630967767)
    h.assert_eq[U64](xorshift128.next(), 16326793230254949856)
    h.assert_eq[U64](xorshift128.next(), 11359508613647406648)
    h.assert_eq[U64](xorshift128.next(), 14128223596631189410)
    h.assert_eq[U64](xorshift128.next(), 13321561208262242495)
    h.assert_eq[U64](xorshift128.next(), 3581557951170338594)
    h.assert_eq[U64](xorshift128.next(), 2578702603722694588)
    h.assert_eq[U64](xorshift128.next(), 17621760581992283265)
    h.assert_eq[U64](xorshift128.next(), 11225999766622519828)
    h.assert_eq[U64](xorshift128.next(), 12292289038289323174)
    h.assert_eq[U64](xorshift128.next(), 12270541530152860305)
    h.assert_eq[U64](xorshift128.next(), 6714726751259523674)
    h.assert_eq[U64](xorshift128.next(), 17401788918532970944)
    h.assert_eq[U64](xorshift128.next(), 9738266245331137221)
    h.assert_eq[U64](xorshift128.next(), 2521714563665930374)
    h.assert_eq[U64](xorshift128.next(), 15419032226133443590)
    h.assert_eq[U64](xorshift128.next(), 14286519144309877787)
    h.assert_eq[U64](xorshift128.next(), 16218131551544384281)
    h.assert_eq[U64](xorshift128.next(), 12989016751868869597)
    h.assert_eq[U64](xorshift128.next(), 3045315264213511453)
    h.assert_eq[U64](xorshift128.next(), 5350971275488356796)
    h.assert_eq[U64](xorshift128.next(), 1161660937480834082)
    h.assert_eq[U64](xorshift128.next(), 14622871003672812064)
    h.assert_eq[U64](xorshift128.next(), 8419339284559328352)
    h.assert_eq[U64](xorshift128.next(), 13022334549981803590)
    h.assert_eq[U64](xorshift128.next(), 7654945617525606649)
    h.assert_eq[U64](xorshift128.next(), 11243084606708396688)
    h.assert_eq[U64](xorshift128.next(), 17348963138446400285)
    h.assert_eq[U64](xorshift128.next(), 4444877400617315043)
    h.assert_eq[U64](xorshift128.next(), 5309453198540110027)
    h.assert_eq[U64](xorshift128.next(), 4833110097864150836)
    h.assert_eq[U64](xorshift128.next(), 12818247497829071300)
    h.assert_eq[U64](xorshift128.next(), 8103385947764579583)
    h.assert_eq[U64](xorshift128.next(), 16807208996761080954)
    h.assert_eq[U64](xorshift128.next(), 16594915043968984071)
    h.assert_eq[U64](xorshift128.next(), 14270645148208935638)
    h.assert_eq[U64](xorshift128.next(), 14332781422233241937)
    h.assert_eq[U64](xorshift128.next(), 7920506732132457340)
    h.assert_eq[U64](xorshift128.next(), 636505475638702567)
    h.assert_eq[U64](xorshift128.next(), 6077012919349679149)
    h.assert_eq[U64](xorshift128.next(), 13727527218047347534)
    h.assert_eq[U64](xorshift128.next(), 17506978699172934773)
    h.assert_eq[U64](xorshift128.next(), 17396260963818494885)
    h.assert_eq[U64](xorshift128.next(), 3389649093821312283)
    h.assert_eq[U64](xorshift128.next(), 14178288864441510364)
    h.assert_eq[U64](xorshift128.next(), 14842545888491587652)
    h.assert_eq[U64](xorshift128.next(), 6439426330783913670)
    h.assert_eq[U64](xorshift128.next(), 13317957523639027716)
    h.assert_eq[U64](xorshift128.next(), 7688825074179778803)
    h.assert_eq[U64](xorshift128.next(), 10872872336590547329)
    h.assert_eq[U64](xorshift128.next(), 1607866797638903357)
    h.assert_eq[U64](xorshift128.next(), 6797260578936901004)
    h.assert_eq[U64](xorshift128.next(), 16399928820249497210)
    h.assert_eq[U64](xorshift128.next(), 4726815332198537617)
    h.assert_eq[U64](xorshift128.next(), 3678906922646043532)
    h.assert_eq[U64](xorshift128.next(), 13146473819500033770)
    h.assert_eq[U64](xorshift128.next(), 12666085170074541801)
    h.assert_eq[U64](xorshift128.next(), 15374844316767921944)
    h.assert_eq[U64](xorshift128.next(), 13374624987652909406)
    h.assert_eq[U64](xorshift128.next(), 11138942897683788563)
    h.assert_eq[U64](xorshift128.next(), 5135084321854884149)
    h.assert_eq[U64](xorshift128.next(), 12829939268385957971)
    h.assert_eq[U64](xorshift128.next(), 7948210577228072758)
    h.assert_eq[U64](xorshift128.next(), 14835791293480411303)
    h.assert_eq[U64](xorshift128.next(), 9622886751459714901)
    h.assert_eq[U64](xorshift128.next(), 9060436523775707368)
    h.assert_eq[U64](xorshift128.next(), 13200352168063138650)
    h.assert_eq[U64](xorshift128.next(), 13361963025075235813)
    h.assert_eq[U64](xorshift128.next(), 2756798064332169055)
    h.assert_eq[U64](xorshift128.next(), 4154380158393262134)
    h.assert_eq[U64](xorshift128.next(), 17632398069149947481)
    h.assert_eq[U64](xorshift128.next(), 6423608242040892287)
    h.assert_eq[U64](xorshift128.next(), 10707002386912431538)
    h.assert_eq[U64](xorshift128.next(), 11005439608704435713)
    h.assert_eq[U64](xorshift128.next(), 18234750837303801640)
    h.assert_eq[U64](xorshift128.next(), 16062417455399828270)
    h.assert_eq[U64](xorshift128.next(), 8838334995162459352)
    h.assert_eq[U64](xorshift128.next(), 15008231500024036016)
    h.assert_eq[U64](xorshift128.next(), 13912767302140890455)
    h.assert_eq[U64](xorshift128.next(), 7178529177267267813)
    h.assert_eq[U64](xorshift128.next(), 13656167702768624163)
    h.assert_eq[U64](xorshift128.next(), 3936651578870932670)
    h.assert_eq[U64](xorshift128.next(), 5634814842780908989)
    h.assert_eq[U64](xorshift128.next(), 1421706706228385425)
    h.assert_eq[U64](xorshift128.next(), 16260336324876548598)
    h.assert_eq[U64](xorshift128.next(), 8359423327609661764)
    h.assert_eq[U64](xorshift128.next(), 12868944303616408673)
    h.assert_eq[U64](xorshift128.next(), 11177430575090270534)
    h.assert_eq[U64](xorshift128.next(), 943079753218141183)
    h.assert_eq[U64](xorshift128.next(), 6344534688474580359)

